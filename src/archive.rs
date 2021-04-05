// Copyright (C) 2021  Franco Bugnano
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use libc::{c_int, c_char, size_t, stat, mode_t};
use std::ffi::{CString, CStr};
use std::error;
use std::fmt;

const ARCHIVE_EOF: c_int = 1;	/* Found end of archive. */
const ARCHIVE_OK: c_int = 0;	/* Operation was successful. */
const ARCHIVE_RETRY: c_int = -10;	/* Retry might succeed. */
const ARCHIVE_WARN: c_int = -20;	/* Partial success. */
const ARCHIVE_FAILED: c_int = -25;	/* Current operation cannot complete. */
const ARCHIVE_FATAL: c_int = -30;	/* No more operations are possible. */

pub const AE_IFMT: mode_t = 0o170000;
pub const AE_IFREG: mode_t = 0o100000;
pub const AE_IFLNK: mode_t = 0o120000;
pub const AE_IFSOCK: mode_t = 0o140000;
pub const AE_IFCHR: mode_t = 0o020000;
pub const AE_IFBLK: mode_t = 0o060000;
pub const AE_IFDIR: mode_t = 0o040000;
pub const AE_IFIFO: mode_t = 0o010000;

#[repr(C)] struct s_archive { _private: [u8; 0] }
#[repr(C)] pub struct s_archive_entry { _private: [u8; 0] }

#[link(name = "archive")]
extern {
	fn archive_read_new() -> *mut s_archive;
	fn archive_read_free(archive: *mut s_archive) -> c_int;
	fn archive_read_support_filter_all(archive: *mut s_archive) -> c_int;
	fn archive_read_support_format_all(archive: *mut s_archive) -> c_int;
	fn archive_read_add_passphrase(archive: *mut s_archive, passphrase: *const c_char) -> c_int;
	fn archive_read_open_filename(archive: *mut s_archive, filename: *const c_char, block_size: size_t) -> c_int;
	fn archive_read_next_header2(archive: *mut s_archive, archive_entry: *mut s_archive_entry) -> c_int;

	fn archive_entry_new() -> *mut s_archive_entry;
	fn archive_entry_free(archive_entry: *mut s_archive_entry);
	fn archive_entry_pathname(a: *mut s_archive_entry) -> *const c_char;
	fn archive_entry_stat(a: *mut s_archive_entry) -> *const stat;

	fn archive_error_string(archive: *mut s_archive) -> *const c_char;
}

#[derive(Debug, Clone)]
pub enum ArchiveError {
	Eof,
	Retry(String),
	Warn(String),
	Failed(String),
	Fatal(String),
	Unknown(c_int, String),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			ArchiveError::Eof => write!(f, "ArchiveError::Eof"),
			ArchiveError::Retry(s) => write!(f, "ArchiveError::Retry({})", s),
			ArchiveError::Warn(s) => write!(f, "ArchiveError::Warn({})", s),
			ArchiveError::Failed(s) => write!(f, "ArchiveError::Failed({})", s),
			ArchiveError::Fatal(s) => write!(f, "ArchiveError::Fatal({})", s),
			ArchiveError::Unknown(n, s) => write!(f, "ArchiveError::Unknown({}, {})", n, s),
		}
    }
}

impl error::Error for ArchiveError {}

unsafe fn string_from_pointer(p: *const c_char) -> String {
	if p.is_null() {
		String::from("")
	} else {
		CStr::from_ptr(p).to_string_lossy().into_owned()
	}
}

fn archive_error_from_int(i: c_int, a: &Archive) -> ArchiveError {
	let s = unsafe { string_from_pointer(archive_error_string(a.archive)) };

	match i {
		ARCHIVE_EOF => ArchiveError::Eof,
		ARCHIVE_RETRY => ArchiveError::Retry(s),
		ARCHIVE_WARN => ArchiveError::Warn(s),
		ARCHIVE_FAILED => ArchiveError::Failed(s),
		ARCHIVE_FATAL => ArchiveError::Fatal(s),
		_ => ArchiveError::Unknown(i, s),
	}
}

#[derive(Debug)]
pub struct Archive {
	archive: *mut s_archive,
}

impl Archive {
	pub fn read_open_filename(filename: &str, block_size: usize, passphrase: Option<&str>) -> Result<Archive, ArchiveError> {
		let a = Archive {
			archive: unsafe { archive_read_new() },
		};

		let mut r = unsafe { archive_read_support_filter_all(a.archive) };
		if r != ARCHIVE_OK {
			return Err(archive_error_from_int(r, &a).into());
		}

		r = unsafe { archive_read_support_format_all(a.archive) };
		if r != ARCHIVE_OK {
			return Err(archive_error_from_int(r, &a).into());
		}

		if let Some(phrase) = passphrase {
			let p = CString::new(phrase).unwrap();
			r = unsafe { archive_read_add_passphrase(a.archive, p.as_ptr()) };
			if r != ARCHIVE_OK {
				return Err(archive_error_from_int(r, &a).into());
			}
		}

		let f = CString::new(filename).unwrap();
		r = unsafe { archive_read_open_filename(a.archive, f.as_ptr(), block_size) };
		if r != ARCHIVE_OK {
			return Err(archive_error_from_int(r, &a).into());
		}

		Ok(a)
	}

	pub fn read_next_header(&self, entry: &mut ArchiveEntry) -> Result<(), ArchiveError> {
		let r = unsafe { archive_read_next_header2(self.archive, entry.archive_entry) };
		if r != ARCHIVE_OK {
			Err(archive_error_from_int(r, &self).into())
		} else {
			Ok(())
		}
	}
}

impl Drop for Archive {
	fn drop(&mut self) {
		unsafe { archive_read_free(self.archive) };
	}
}

#[derive(Debug)]
pub struct ArchiveEntry {
	archive_entry: *mut s_archive_entry,
}

impl ArchiveEntry {
	pub fn new() -> ArchiveEntry {
		ArchiveEntry {
			archive_entry: unsafe { archive_entry_new() },
		}
	}

	pub fn pathname(&self) -> String {
		unsafe { string_from_pointer(archive_entry_pathname(self.archive_entry)) }
	}

	pub fn stat(&self) -> stat {
		unsafe {
			let s = archive_entry_stat(self.archive_entry);

			if s.is_null() {
				std::mem::zeroed()
			} else {
				*s
			}
		}
	}
}

impl Drop for ArchiveEntry {
	fn drop(&mut self) {
		unsafe { archive_entry_free(self.archive_entry) };
	}
}

