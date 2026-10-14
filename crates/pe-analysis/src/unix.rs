//! Linux and macOS counterparts of the Windows file checks: network / removable drive of the
//! analysed file and its access control (the "acl" footprint).

use std::path::Path;

/// (network, removable) for the file system holding `path`.
pub fn drive_kind(path: &Path) -> (bool, bool) {
    let full = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    imp::drive_kind(&full)
}

/// Owner, group, mode and ACL of the file, as bytes to hash (the counterpart of the Windows
/// security descriptor).
pub fn access_control(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    let mut out = format!("uid={} gid={} mode={:o}\n", m.uid(), m.gid(), m.mode() & 0o7777).into_bytes();
    if let Some(acl) = imp::acl(path) {
        out.extend_from_slice(&acl);
    }
    Some(out)
}

/// Network file systems by `statfs` magic number (Linux).
pub const NETWORK_FS_MAGIC: [(i64, &str); 9] = [
    (0x6969, "nfs"),
    (0x517B, "smb"),
    (0xFF53_4D42, "cifs"),
    (0xFE53_4D42, "smb2"),
    (0x564C, "ncp"),
    (0x7375_7245, "coda"),
    (0x5346_414F, "afs"),
    (0x0102_1997, "9p"),
    (0x0BD0_0BD0, "lustre"),
];

/// Network file systems by `statfs` type name (macOS).
pub const NETWORK_FS_NAMES: [&str; 6] = ["smbfs", "afpfs", "nfs", "webdav", "ftp", "cifs"];

fn c_path(path: &Path) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).ok()
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    pub fn drive_kind(path: &Path) -> (bool, bool) {
        let Some(c) = c_path(path) else { return (false, false) };
        // SAFETY: `c` is NUL-terminated and `st` is a valid out-parameter.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        let network = unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 && NETWORK_FS_MAGIC.iter().any(|(m, _)| st.f_type as i64 == *m);
        (network, !network && removable(path))
    }

    /// The block device holding the file is removable (USB stick, SD card, external USB disk).
    fn removable(path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Ok(m) = std::fs::metadata(path) else { return false };
        let dev = m.dev();
        let (major, minor) = (libc::major(dev), libc::minor(dev));
        let Ok(sys) = std::fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")) else { return false };
        if sys.to_string_lossy().contains("/usb") {
            return true;
        }
        // a partition's "removable" flag is on its disk (the parent directory)
        [sys.join("removable"), sys.parent().map(|p| p.join("removable")).unwrap_or_default()]
            .iter()
            .any(|f| std::fs::read_to_string(f).is_ok_and(|v| v.trim() == "1"))
    }

    /// POSIX access ACL (extended attribute "system.posix_acl_access").
    pub fn acl(path: &Path) -> Option<Vec<u8>> {
        let c = c_path(path)?;
        let name = c"system.posix_acl_access";
        let mut buf = vec![0u8; 4096];
        // SAFETY: valid NUL-terminated strings and a buffer of the given length.
        let n = unsafe { libc::getxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        (n > 0).then(|| {
            buf.truncate(n as usize);
            buf
        })
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub fn drive_kind(path: &Path) -> (bool, bool) {
        let Some(c) = c_path(path) else { return (false, false) };
        // SAFETY: `c` is NUL-terminated and `st` is a valid out-parameter.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
            return (false, false);
        }
        let fstype = unsafe { std::ffi::CStr::from_ptr(st.f_fstypename.as_ptr()) }.to_string_lossy().into_owned();
        let network = st.f_flags & libc::MNT_LOCAL as u32 == 0 || NETWORK_FS_NAMES.contains(&fstype.as_str());
        if network {
            return (true, false);
        }
        let device = unsafe { std::ffi::CStr::from_ptr(st.f_mntfromname.as_ptr()) }.to_string_lossy().into_owned();
        (false, removable(&device))
    }

    /// `diskutil info -plist <device>`: an external or ejectable device.
    fn removable(device: &str) -> bool {
        let Ok(o) = std::process::Command::new("/usr/sbin/diskutil").args(["info", "-plist", device]).output() else { return false };
        let plist = String::from_utf8_lossy(&o.stdout);
        let flag = |key: &str| {
            plist
                .find(&format!("<key>{key}</key>"))
                .map(|i| plist[i..].split_once("</key>").map(|x| x.1.trim_start().starts_with("<true/>")))
        };
        flag("Internal").flatten() == Some(false)
            || flag("Ejectable").flatten() == Some(true)
            || flag("RemovableMedia").flatten() == Some(true)
    }

    unsafe extern "C" {
        fn acl_get_file(path: *const libc::c_char, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_to_text(acl: *mut libc::c_void, len: *mut libc::ssize_t) -> *mut libc::c_char;
        fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
    }
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    /// Extended ACL (acl_get_file / acl_to_text).
    pub fn acl(path: &Path) -> Option<Vec<u8>> {
        let c = c_path(path)?;
        // SAFETY: the ACL and its text are freed with acl_free; null results are checked.
        unsafe {
            let acl = acl_get_file(c.as_ptr(), ACL_TYPE_EXTENDED);
            if acl.is_null() {
                return None;
            }
            let text = acl_to_text(acl, std::ptr::null_mut());
            let out = (!text.is_null()).then(|| std::ffi::CStr::from_ptr(text).to_bytes().to_vec());
            if !text.is_null() {
                acl_free(text.cast());
            }
            acl_free(acl);
            out
        }
    }
}

/// Other Unix systems (BSD, …): mode/owner only, no drive information.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use super::*;

    pub fn drive_kind(_path: &Path) -> (bool, bool) {
        (false, false)
    }

    pub fn acl(_path: &Path) -> Option<Vec<u8>> {
        None
    }
}
