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

use libc::{c_int, c_char, size_t};
use std::ffi::{CString, CStr};
use std::error;
use std::fmt;

const ARCHIVE_EOF: c_int = 1;	/* Found end of archive. */
const ARCHIVE_OK: c_int = 0;	/* Operation was successful. */
const ARCHIVE_RETRY: c_int = -10;	/* Retry might succeed. */
const ARCHIVE_WARN: c_int = -20;	/* Partial success. */
const ARCHIVE_FAILED: c_int = -25;	/* Current operation cannot complete. */
const ARCHIVE_FATAL: c_int = -30;	/* No more operations are possible. */

#[repr(C)] struct s_archive { _private: [u8; 0] }
#[repr(C)] pub struct s_archive_entry { _private: [u8; 0] }

#[link(name = "archive")]
extern {
	fn archive_read_new() -> *mut s_archive;
	fn archive_read_free(archive: *mut s_archive) -> c_int;
	fn archive_read_support_filter_all(archive: *mut s_archive) -> c_int;
	fn archive_read_support_format_all(archive: *mut s_archive) -> c_int;
	fn archive_read_open_filename(archive: *mut s_archive, filename: *const c_char, block_size: size_t) -> c_int;
	fn archive_read_next_header2(archive: *mut s_archive, archive_entry: *mut s_archive_entry) -> c_int;

	fn archive_entry_new() -> *mut s_archive_entry;
	fn archive_entry_free(archive_entry: *mut s_archive_entry);
	fn archive_entry_pathname(a: *mut s_archive_entry) -> *const c_char;
}

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone)]
pub enum ArchiveError {
	Eof,
	Retry,
	Warn,
	Failed,
	Fatal,
	Unknown(c_int),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			ArchiveError::Eof => write!(f, "ArchiveError::Eof"),
			ArchiveError::Retry => write!(f, "ArchiveError::Retry"),
			ArchiveError::Warn => write!(f, "ArchiveError::Warn"),
			ArchiveError::Failed => write!(f, "ArchiveError::Failed"),
			ArchiveError::Fatal => write!(f, "ArchiveError::Fatal"),
			ArchiveError::Unknown(n) => write!(f, "ArchiveError::Unknown({})", n),
		}
    }
}

impl error::Error for ArchiveError {}

fn archive_error_from_int(i: c_int) -> ArchiveError {
	match i {
		ARCHIVE_EOF => ArchiveError::Eof,
		ARCHIVE_RETRY => ArchiveError::Retry,
		ARCHIVE_WARN => ArchiveError::Warn,
		ARCHIVE_FAILED => ArchiveError::Failed,
		ARCHIVE_FATAL => ArchiveError::Fatal,
		_ => ArchiveError::Unknown(i),
	}
}

#[derive(Debug)]
pub struct Archive {
	archive: *mut s_archive,
}

impl Archive {
	pub fn read_open_filename(filename: &str, block_size: usize) -> Result<Archive> {
		let a = Archive {
			archive: unsafe { archive_read_new() },
		};

		let mut r = unsafe { archive_read_support_filter_all(a.archive) };
		if r != ARCHIVE_OK {
			return Err(archive_error_from_int(r).into());
		}

		r = unsafe { archive_read_support_format_all(a.archive) };
		if r != ARCHIVE_OK {
			return Err(archive_error_from_int(r).into());
		}

		let f = CString::new(filename)?;
		r = unsafe { archive_read_open_filename(a.archive, f.as_ptr(), block_size) };
		if r != ARCHIVE_OK {
			return Err(archive_error_from_int(r).into());
		}

		Ok(a)
	}

	pub fn read_next_header(&self, entry: &mut ArchiveEntry) -> Result<()> {
		let r = unsafe { archive_read_next_header2(self.archive, entry.archive_entry) };
		if r != ARCHIVE_OK {
			Err(archive_error_from_int(r).into())
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
		unsafe { CStr::from_ptr(archive_entry_pathname(self.archive_entry)).to_string_lossy().into_owned() }
	}
}

impl Drop for ArchiveEntry {
	fn drop(&mut self) {
		unsafe { archive_entry_free(self.archive_entry) };
	}
}

