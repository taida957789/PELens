//! Authenticode verification through WinVerifyTrust (Windows only).

use crate::model::CertificateCheck;

pub fn trust_message(code: i32) -> String {
    match code as u32 {
        0 => "This digital signature is OK.".into(),
        0x800B_0100 => "No signature was present in the subject.".into(),
        0x8009_6010 => "The digital signature of the object did not verify (bad digest).".into(),
        0x800B_0101 => "A required certificate is not within its validity period.".into(),
        0x800B_0109 => "The certificate chain terminates in an untrusted root.".into(),
        0x800B_010C => "A certificate was explicitly revoked by its issuer.".into(),
        0x800B_0111 => "The certificate was explicitly marked as untrusted.".into(),
        0x800B_0004 => "The subject is not trusted for the specified action.".into(),
        0x800B_0003 => "The form specified for the subject is not supported.".into(),
        c => format!("error-code: 0x{c:08X}"),
    }
}

#[cfg(windows)]
pub fn verify_path(path: &str) -> CertificateCheck {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::WinTrust::*;
    let wide: Vec<u16> = std::ffi::OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    // SAFETY: WINTRUST_DATA is a plain C struct; all-zero is a valid initial state.
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: pointers reference live stack values for the duration of both calls.
    let code = unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut core::ffi::c_void) };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: as above; releases the state allocated by the verify call.
    unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut core::ffi::c_void) };
    CertificateCheck { verified: Some(code == 0), message: trust_message(code) }
}

#[cfg(not(windows))]
pub fn verify_path(_path: &str) -> CertificateCheck {
    CertificateCheck { verified: None, message: "verification not available on this platform".into() }
}
