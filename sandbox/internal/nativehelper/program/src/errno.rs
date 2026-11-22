//! Error text. A failure the runner reports (as the run's detail, or a step's stderr) starts
//! with the error's code, as Node's does (`EISDIR: ...`), and is compared by that code, not
//! by Node's wording (the choice recorded on the status page, finding rust-native-helper-21):
//! `CODE: description, syscall 'path'`.

use std::io;

/// Linux's name for an error number, for the ones a runner can meet.
pub fn name(code: i32) -> Option<&'static str> {
    Some(match code {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        26 => "ETXTBSY",
        27 => "EFBIG",
        28 => "ENOSPC",
        29 => "ESPIPE",
        30 => "EROFS",
        31 => "EMLINK",
        32 => "EPIPE",
        36 => "ENAMETOOLONG",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        75 => "EOVERFLOW",
        95 => "EOPNOTSUPP",
        105 => "ENOBUFS",
        110 => "ETIMEDOUT",
        122 => "EDQUOT",
        _ => return None,
    })
}

/// The error's code name, or `errno N` for one without a name here, or `unknown` for an
/// error that carries no number.
pub fn code(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => name(n).map_or_else(|| format!("errno {n}"), str::to_owned),
        None => "unknown".to_owned(),
    }
}

/// `CODE: description, syscall 'path'`, the description the C library's own, first letter
/// lowercased (`EISDIR: is a directory, open '/work'`).
pub fn describe(e: &io::Error, syscall: &str, path: &str) -> String {
    let text = e.to_string();
    let text = text.rsplit_once(" (os error ").map_or(text.as_str(), |(t, _)| t);
    let mut chars = text.chars();
    let lowered = match chars.next() {
        Some(c) => c.to_lowercase().chain(chars).collect::<String>(),
        None => String::new(),
    };
    format!("{}: {lowered}, {syscall} '{path}'", code(e))
}

#[cfg(test)]
mod tests {
    use super::{code, describe, name};
    use std::io;

    #[test]
    fn names_and_text() {
        assert_eq!(name(21), Some("EISDIR"));
        assert_eq!(name(36), Some("ENAMETOOLONG"));
        assert_eq!(code(&io::Error::from_raw_os_error(7)), "E2BIG");
        assert_eq!(code(&io::Error::from_raw_os_error(200)), "errno 200");
        let d = describe(&io::Error::from_raw_os_error(21), "open", "/work");
        assert!(d.starts_with("EISDIR: is a directory"), "{d}");
        assert!(d.ends_with(", open '/work'"), "{d}");
    }
}
