//! Windows desktop following: keep a capture / input thread attached to the *input desktop*.
//!
//! Windows shows the UAC prompt and the lock / login screen on a separate desktop
//! (`Winlogon`). A thread only captures and injects into the desktop it is attached to,
//! so each worker thread periodically checks `OpenInputDesktop` and, when the input desktop
//! changed, moves itself there with `SetThreadDesktop`. This only succeeds for a SYSTEM
//! process (the RustDesk model: a LocalSystem service spawns the worker in the console
//! session). A normal-user process can't open `Winlogon`; it stays where it is and the
//! viewer is shown the "secure desktop" notice instead.
//!
//! On other platforms everything here is a no-op.

use std::time::{Duration, Instant};

/// How often the input desktop is re-checked (cheap, but not per frame).
pub const CHECK_EVERY: Duration = Duration::from_millis(250);

#[cfg(windows)]
pub use imp::*;

#[cfg(not(windows))]
pub use stub::*;

#[cfg(not(windows))]
mod stub {
    use super::*;

    /// No-op on non-Windows platforms.
    #[derive(Default)]
    pub struct DesktopFollower {
        _last: Option<Instant>,
    }

    impl DesktopFollower {
        pub fn new() -> Self {
            Self::default()
        }
        /// Never switches; there is only one desktop.
        pub fn follow(&mut self) -> Option<String> {
            let _ = CHECK_EVERY;
            None
        }
        pub fn on_input_desktop(&self) -> bool {
            false
        }
    }

    pub fn on_secure_desktop() -> bool {
        false
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use tracing::{info, warn};
    use windows_sys::Win32::{
        Foundation::{GetLastError, GENERIC_ALL},
        Graphics::Gdi::{
            BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, GetDIBits, ReleaseDC,
            SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS, SRCCOPY,
        },
        System::{
            StationsAndDesktops::{
                CloseDesktop, GetThreadDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop,
                DESKTOP_READOBJECTS, HDESK, UOI_NAME,
            },
            Threading::GetCurrentThreadId,
        },
        UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN},
    };

    /// Keeps the calling thread on the current input desktop. Create and use it on the
    /// thread that captures / injects: `SetThreadDesktop` affects only the calling thread
    /// (and fails if that thread owns windows or hooks).
    pub struct DesktopFollower {
        /// Desktop handle we attached to (null = still on the thread's original desktop,
        /// which belongs to the system and must not be closed).
        owned: HDESK,
        on_input: bool,
        last_check: Option<Instant>,
        /// Last failure logged, so a persistent error isn't repeated every 250 ms.
        last_err: Option<u32>,
    }

    // SAFETY: never moved across threads in practice (built inside the worker thread),
    // and a desktop handle is just a kernel handle value.
    unsafe impl Send for DesktopFollower {}

    impl Default for DesktopFollower {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DesktopFollower {
        pub fn new() -> Self {
            Self { owned: std::ptr::null_mut(), on_input: false, last_check: None, last_err: None }
        }

        /// Whether, at the last check, this thread was attached to the input desktop.
        pub fn on_input_desktop(&self) -> bool {
            self.on_input
        }

        /// Rate-limited to [`CHECK_EVERY`]. Returns the new desktop name when this thread
        /// was just moved to a different desktop; callers must then recreate anything bound
        /// to the old one (capture handles, the `Enigo` instance).
        pub fn follow(&mut self) -> Option<String> {
            if self.last_check.is_some_and(|t| t.elapsed() < CHECK_EVERY) {
                return None;
            }
            self.last_check = Some(Instant::now());
            unsafe {
                let desk = OpenInputDesktop(0, 0, GENERIC_ALL);
                if desk.is_null() {
                    // Expected for a non-SYSTEM process while Winlogon is up.
                    self.on_input = false;
                    self.log_err("OpenInputDesktop", GetLastError());
                    return None;
                }
                let name = desktop_name(desk).unwrap_or_default();
                let current = desktop_name(GetThreadDesktop(GetCurrentThreadId())).unwrap_or_default();
                if name.eq_ignore_ascii_case(&current) {
                    CloseDesktop(desk);
                    self.on_input = true;
                    self.last_err = None;
                    return None;
                }
                if SetThreadDesktop(desk) == 0 {
                    let err = GetLastError();
                    CloseDesktop(desk);
                    self.on_input = false;
                    self.log_err("SetThreadDesktop", err);
                    return None;
                }
                if !self.owned.is_null() {
                    CloseDesktop(self.owned);
                }
                self.owned = desk;
                self.on_input = true;
                self.last_err = None;
                info!(
                    "thread {:?} switched desktop {current:?} -> {name:?}",
                    std::thread::current().name().unwrap_or("?")
                );
                Some(name)
            }
        }

        fn log_err(&mut self, what: &str, err: u32) {
            if self.last_err != Some(err) {
                self.last_err = Some(err);
                // 5 = ERROR_ACCESS_DENIED (not SYSTEM); 170 = ERROR_BUSY (thread owns windows/hooks).
                warn!("{what} failed (error {err}); staying on the current desktop");
            }
        }
    }

    impl Drop for DesktopFollower {
        fn drop(&mut self) {
            if !self.owned.is_null() {
                // Fails harmlessly while the handle is still the thread's desktop.
                unsafe { CloseDesktop(self.owned) };
            }
        }
    }

    unsafe fn desktop_name(desk: HDESK) -> Option<String> {
        if desk.is_null() {
            return None;
        }
        let mut name = [0u16; 64];
        let mut needed = 0u32;
        let ok = GetUserObjectInformationW(desk, UOI_NAME, name.as_mut_ptr().cast(), (name.len() * 2) as u32, &mut needed);
        if ok == 0 {
            return None;
        }
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        Some(String::from_utf16_lossy(&name[..len]))
    }

    /// Is the input desktop something other than the user's normal one?
    /// That's the UAC "secure desktop" or the lock / login screen (`Winlogon`). A normal-user
    /// process can't open that desktop at all, so an access failure also means "secure".
    pub fn on_secure_desktop() -> bool {
        unsafe {
            let desk = OpenInputDesktop(0, 0, DESKTOP_READOBJECTS);
            if desk.is_null() {
                return true;
            }
            let name = desktop_name(desk);
            CloseDesktop(desk);
            match name {
                Some(n) => !n.eq_ignore_ascii_case("Default"),
                None => false, // can't tell; let the capture result decide
            }
        }
    }

    /// Size of the primary screen, used when no monitor list is available.
    pub fn primary_rect() -> (i32, i32, i32, i32) {
        unsafe { (0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) }
    }

    /// Plain GDI capture of a virtual-screen rectangle on the calling thread's desktop
    /// (`GetDC(NULL)` + `BitBlt` + `GetDIBits`). Slower than DXGI but works on `Winlogon`
    /// for a SYSTEM thread attached to it. Returns RGBA.
    pub fn gdi_capture(x: i32, y: i32, w: i32, h: i32) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(w > 0 && h > 0, "empty capture rect {w}x{h}");
        unsafe {
            let screen = GetDC(std::ptr::null_mut());
            anyhow::ensure!(!screen.is_null(), "GetDC(NULL) failed ({})", GetLastError());
            let mem = CreateCompatibleDC(screen);
            let bmp = CreateCompatibleBitmap(screen, w, h);
            let result = (|| {
                anyhow::ensure!(!mem.is_null() && !bmp.is_null(), "GDI allocation failed ({})", GetLastError());
                let old = SelectObject(mem, bmp);
                let blt = BitBlt(mem, 0, 0, w, h, screen, x, y, SRCCOPY | CAPTUREBLT);
                SelectObject(mem, old);
                anyhow::ensure!(blt != 0, "BitBlt failed ({})", GetLastError());

                let mut info: BITMAPINFO = std::mem::zeroed();
                info.bmiHeader = BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: w,
                    biHeight: -h, // top-down rows
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB as _,
                    ..std::mem::zeroed()
                };
                let mut buf = vec![0u8; w as usize * h as usize * 4];
                let lines = GetDIBits(mem, bmp, 0, h as u32, buf.as_mut_ptr().cast(), &mut info, DIB_RGB_COLORS);
                anyhow::ensure!(lines == h, "GetDIBits returned {lines} of {h} lines ({})", GetLastError());
                // BGRA → RGBA, opaque.
                for px in buf.as_chunks_mut::<4>().0 {
                    px.swap(0, 2);
                    px[3] = 255;
                }
                Ok(buf)
            })();
            if !bmp.is_null() {
                DeleteObject(bmp);
            }
            if !mem.is_null() {
                DeleteDC(mem);
            }
            ReleaseDC(std::ptr::null_mut(), screen);
            result
        }
    }
}
