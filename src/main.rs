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

use std::ffi::{OsStr, OsString};
use std::time::{Duration, UNIX_EPOCH};
use libc::{ENOENT};
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyData, ReplyEntry, ReplyAttr, ReplyDirectory};
use clap::{Arg, App};
use std::os::unix::io::AsRawFd;
use termios::{Termios, tcsetattr, ECHO, TCSANOW};

mod archive;

use archive::{Archive, ArchiveEntry, ArchiveError};

const TTL: Duration = Duration::from_secs(1);			// 1 second

const HELLO_DIR_ATTR: FileAttr = FileAttr {
	ino: 1,
	size: 0,
	blocks: 0,
	atime: UNIX_EPOCH,									// 1970-01-01 00:00:00
	mtime: UNIX_EPOCH,
	ctime: UNIX_EPOCH,
	crtime: UNIX_EPOCH,
	kind: FileType::Directory,
	perm: 0o755,
	nlink: 2,
	uid: 501,
	gid: 20,
	rdev: 0,
	flags: 0,
};

const HELLO_TXT_CONTENT: &str = "Hello World!\n";

const HELLO_TXT_ATTR: FileAttr = FileAttr {
	ino: 2,
	size: 13,
	blocks: 1,
	atime: UNIX_EPOCH,									// 1970-01-01 00:00:00
	mtime: UNIX_EPOCH,
	ctime: UNIX_EPOCH,
	crtime: UNIX_EPOCH,
	kind: FileType::RegularFile,
	perm: 0o644,
	nlink: 1,
	uid: 501,
	gid: 20,
	rdev: 0,
	flags: 0,
};

#[derive(Debug)]
struct ArchiveFS {
	archive_path: String,
	password: Option<String>,
	entries: Vec<FileAttr>,
}

impl Filesystem for ArchiveFS {
	fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
		if parent == 1 && name.to_str() == Some("hello.txt") {
			reply.entry(&TTL, &HELLO_TXT_ATTR, 0);
		} else {
			reply.error(ENOENT);
		}
	}

	fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
		match ino {
			1 => reply.attr(&TTL, &HELLO_DIR_ATTR),
			2 => reply.attr(&TTL, &HELLO_TXT_ATTR),
			_ => reply.error(ENOENT),
		}
	}

	fn read(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, _size: u32, reply: ReplyData) {
		if ino == 2 {
			reply.data(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..]);
		} else {
			reply.error(ENOENT);
		}
	}

	fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
		if ino != 1 {
			reply.error(ENOENT);
			return;
		}

		let entries = vec![
			(1, FileType::Directory, "."),
			(1, FileType::Directory, ".."),
			(2, FileType::RegularFile, "hello.txt"),
		];

		for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
			// i + 1 means the index of the next entry
			reply.add(entry.0, (i + 1) as i64, entry.1, entry.2);
		}
		reply.ok();
	}
}

fn main() {
	let matches = App::new("archivemount-rs")
		.version("0.1.0")
		.author("Franco Bugnano")
		.about("Mount an archive file as a read-only file system")
		.arg(Arg::with_name("ARCHIVEPATH")
			.help("Archive file")
			.required(true)
			.index(1))
		.arg(Arg::with_name("MOUNTPOINT")
			.help("Mount point")
			.required(true)
			.index(2))
		.arg(Arg::with_name("password")
			.short("p")
			.long("password")
			.help("Open a password encrypted archive"))
		.arg(Arg::with_name("o")
			.short("o")
			.multiple(true)
			.takes_value(true)
			.number_of_values(1)
			.value_name("OPTION")
			.help("FUSE mount option"))
		.get_matches();

	let mut fs = ArchiveFS {
		archive_path: String::from(matches.value_of("ARCHIVEPATH").unwrap()),
		password: {
			if matches.is_present("password") {
				let mut password = String::new();
				eprint!("Enter passphrase:");
				let stdin = std::io::stdin();
				let fd = stdin.as_raw_fd();
				let mut t = Termios::from_fd(fd).unwrap();
				t.c_lflag &= !ECHO;
				tcsetattr(fd, TCSANOW, &t).unwrap();
				stdin.read_line(&mut password).unwrap();
				t.c_lflag |= ECHO;
				tcsetattr(fd, TCSANOW, &t).unwrap();
				eprintln!("");

				Some(String::from(password.trim_end_matches('\n')))
			} else {
				None
			}
		},
		entries: Vec::new(),
	};

	let mut ino = 2;
	let mut entry = ArchiveEntry::new();
	let a = match Archive::read_open_filename(&fs.archive_path, 10240, None) {
		Ok(a) => a,
		Err(ArchiveError::Eof) => panic!("EOF"),
		Err(ArchiveError::Retry(s)) => panic!("{}", s),
		Err(ArchiveError::Warn(s)) => panic!("{}", s),
		Err(ArchiveError::Failed(s)) => panic!("{}", s),
		Err(ArchiveError::Fatal(s)) => panic!("{}", s),
		Err(ArchiveError::Unknown(_, s)) => panic!("{}", s),
	};

	loop {
		match a.read_next_header(&mut entry) {
			Ok(()) => {
				let st = entry.stat();
				println!("{}", entry.pathname());
				let kind = match st.st_mode & archive::AE_IFMT {
					archive::AE_IFREG => FileType::RegularFile,
					archive::AE_IFLNK => FileType::Symlink,
					archive::AE_IFSOCK => FileType::Socket,
					archive::AE_IFCHR => FileType::CharDevice,
					archive::AE_IFBLK => FileType::BlockDevice,
					archive::AE_IFDIR => FileType::Directory,
					archive::AE_IFIFO => FileType::NamedPipe,
					_ => FileType::RegularFile,
				};

				let attr = FileAttr {
					ino: ino,
					size: st.st_size as u64,
					blocks: ((st.st_size + 511) / 512) as u64,
					atime: UNIX_EPOCH + Duration::new(st.st_atime as u64, st.st_atime_nsec as u32),
					mtime: UNIX_EPOCH + Duration::new(st.st_mtime as u64, st.st_mtime_nsec as u32),
					ctime: UNIX_EPOCH + Duration::new(st.st_ctime as u64, st.st_ctime_nsec as u32),
					crtime: UNIX_EPOCH,
					kind: kind,
					perm: (st.st_mode & 0o7777) as u16,
					nlink: {
						if (kind == FileType::Directory) && (st.st_nlink < 2) {
							2
						} else if st.st_nlink < 1 {
							1
						} else {
							st.st_nlink as u32
						}
					},
					uid: st.st_uid,
					gid: st.st_gid,
					rdev: st.st_rdev as u32,
					flags: 0,
				};
				fs.entries.push(attr);

				ino += 1;

				println!("{:?}", attr);
				println!("{}", st.st_mode);
			},
			Err(e) => {
				println!("{:?}", e);
				break;
			}
		}
	}

	let mut options: Vec<OsString> = Vec::new();

	if let Some(o) = matches.values_of_os("o") {
		for option in o {
			options.push(OsString::from("-o"));
			options.push(option.to_os_string());
		}
	}

	let mountpoint = matches.value_of("MOUNTPOINT").unwrap();
	let options = options
		.iter()
		.map(|o| o.as_ref())
		.collect::<Vec<&OsStr>>();

	println!("{:?}", options);
	println!("{:?}", fs);
	fuse::mount(fs, mountpoint, &options).unwrap();
}

