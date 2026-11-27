//! Windows security helpers for the service / worker: SDDL security descriptors (named
//! pipes, the `%ProgramData%\Veyndesk` folder), sessions and the logged-on user.

use std::{ffi::c_void, path::Path, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_USER,
    },
    System::{
        RemoteDesktop::{ProcessIdToSessionId, WTSQueryUserToken},
        Threading::GetCurrentProcessId,
    },
};

/// Full control for SYSTEM and Administrators only, inherited by everything inside.
pub const ADMIN_ONLY_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

/// A `SECURITY_ATTRIBUTES` built from an SDDL string. Keep it alive while the object it
/// is passed to is being created.
pub struct SecurityAttributes {
    sd: PSECURITY_DESCRIPTOR,
    sa: SECURITY_ATTRIBUTES,
}

// SAFETY: owns a LocalAlloc'ed, immutable security descriptor.
unsafe impl Send for SecurityAttributes {}
unsafe impl Sync for SecurityAttributes {}

impl SecurityAttributes {
    pub fn from_sddl(sddl: &str) -> anyhow::Result<Self> {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let w = wide(sddl);
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
        };
        anyhow::ensure!(ok != 0, "invalid SDDL {sddl:?}: {}", std::io::Error::last_os_error());
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        Ok(Self { sd, sa })
    }

    /// Pointer suitable for `CreateNamedPipeW` & co. Valid while `self` lives.
    pub fn as_ptr(&mut self) -> *mut c_void {
        (&mut self.sa as *mut SECURITY_ATTRIBUTES).cast()
    }

    fn dacl(&self) -> anyhow::Result<*mut ACL> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = null_mut();
        let ok = unsafe { GetSecurityDescriptorDacl(self.sd, &mut present, &mut dacl, &mut defaulted) };
        anyhow::ensure!(ok != 0 && present != 0, "SDDL has no DACL");
        Ok(dacl)
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        unsafe { LocalFree(self.sd) };
    }
}

/// Replace the DACL of a file or folder (protected: nothing inherited from the parent).
/// For a folder, inheritable entries are propagated to what is already inside.
pub fn protect_path(path: &Path, sddl: &str) -> anyhow::Result<()> {
    let sa = SecurityAttributes::from_sddl(sddl)?;
    let dacl = sa.dacl()?;
    let w = wide(path.as_os_str());
    let err = unsafe {
        SetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    anyhow::ensure!(err == 0, "SetNamedSecurityInfoW({}) failed: error {err}", path.display());
    Ok(())
}

/// Terminal-services session of this process (1 = usually the first console user).
pub fn current_session() -> u32 {
    let mut s = 0;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut s) };
    s
}

/// SID (`S-1-5-21-…`) of the user logged on to `session`, or `None` on the login screen.
/// Requires SYSTEM (`WTSQueryUserToken`).
pub fn session_user_sid(session: u32) -> Option<String> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if WTSQueryUserToken(session, &mut token) == 0 {
            return None;
        }
        let mut buf = vec![0u64; 64]; // u64: TOKEN_USER holds pointers
        let mut len = 0u32;
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s: windows_sys::core::PWSTR = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut s) == 0 {
            return None;
        }
        let len = (0..).take_while(|&i| *s.add(i) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(s, len));
        LocalFree(s.cast());
        Some(sid)
    }
}
