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
use std::ffi::{CString};
use std::error;
use std::fmt;

#[repr(C)] pub struct archive { _private: [u8; 0] }
#[repr(C)] pub struct archive_entry { _private: [u8; 0] }

const ARCHIVE_EOF: c_int = 1;	/* Found end of archive. */
const ARCHIVE_OK: c_int = 0;	/* Operation was successful. */
const ARCHIVE_RETRY: c_int = -10;	/* Retry might succeed. */
const ARCHIVE_WARN: c_int = -20;	/* Partial success. */
const ARCHIVE_FAILED: c_int = -25;	/* Current operation cannot complete. */
const ARCHIVE_FATAL: c_int = -30;	/* No more operations are possible. */

#[link(name = "archive")]
extern {
	fn archive_read_new() -> *mut archive;
	fn archive_read_support_filter_all(a: *mut archive) -> c_int;
	fn archive_read_support_format_all(a: *mut archive) -> c_int;
	fn archive_read_open_filename(a: *mut archive, filename: *const c_char, block_size: size_t) -> c_int;
}

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
	a: *mut archive,
}

impl Archive {
	pub fn read_open_filename(filename: &str, block_size: size_t) -> Result<Archive, ArchiveError> {
		let a = Archive {
			a: unsafe { archive_read_new() },
		};

		let mut r = unsafe { archive_read_support_filter_all(a.a) };
		if r != ARCHIVE_OK {
			return Err(archive_error_from_int(r));
		}

		r = unsafe { archive_read_support_format_all(a.a) };
		if r != ARCHIVE_OK {
			return Err(archive_error_from_int(r));
		}

		{
			let f = CString::new(filename).unwrap();
			r = unsafe { archive_read_open_filename(a.a, f.as_ptr(), block_size) };
			if r != ARCHIVE_OK {
				return Err(archive_error_from_int(r));
			}
		}

		Ok(a)
	}
}

