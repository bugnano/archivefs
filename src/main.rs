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

use polyfuse::{
	op,
	reply::{AttrOut, EntryOut, FileAttr, ReaddirOut, StatfsOut},
	KernelConfig, Operation, Request, Session,
};

use anyhow::{ensure, Result, bail};
use std::{io, os::unix::prelude::*, path::PathBuf, time::Duration};

use clap::{Arg, App, crate_version};
use std::os::unix::io::AsRawFd;
use termios::{Termios, tcsetattr, ECHO, TCSANOW};

mod archive;

use archive::{Archive, ArchiveEntry, ArchiveError};

const TTL: Duration = Duration::from_secs(60 * 60 * 24 * 365);
const ROOT_INO: u64 = 1;
const HELLO_INO: u64 = 2;
const HELLO_FILENAME: &str = "hello.txt";
const HELLO_CONTENT: &[u8] = b"Hello, world!\n";

#[derive(Debug)]
struct DirEntry {
	name: String,
	ino: u64,
	typ: u32,

	size: u64,
	blksize: u32,
	blocks: u64,
	atime: Duration,
	mtime: Duration,
	ctime: Duration,
	mode: u32,
	nlink: u32,
	uid: u32,
	gid: u32,
	rdev: u32,
}

impl DirEntry {
	fn fill_attr(&self, attr: &mut FileAttr) {
		attr.ino(self.ino);
		attr.size(self.size);
		attr.blksize(self.blksize);
		attr.blocks(self.blocks);
		attr.atime(self.atime);
		attr.mtime(self.mtime);
		attr.ctime(self.ctime);
		attr.mode(self.mode);
		attr.nlink(self.nlink);
		attr.uid(self.uid);
		attr.gid(self.gid);
		attr.rdev(self.rdev);
	}
}

#[derive(Debug)]
struct ArchiveFS {
	archive_path: String,
	password: Option<String>,
	entries: Vec<DirEntry>,
}

impl ArchiveFS {
	fn lookup(&self, req: &Request, op: op::Lookup<'_>) -> io::Result<()> {
		match op.parent() {
			ROOT_INO if op.name().as_bytes() == HELLO_FILENAME.as_bytes() => {
				let mut out = EntryOut::default();
				self.entries[2].fill_attr(out.attr());
				out.ino(HELLO_INO);
				out.ttl_attr(TTL);
				out.ttl_entry(TTL);
				req.reply(out)
			}
			_ => req.reply_error(libc::ENOENT),
		}
	}

	fn getattr(&self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
		let mut out = AttrOut::default();

		match op.ino() {
			ROOT_INO => self.entries[0].fill_attr(out.attr()),
			HELLO_INO => self.entries[2].fill_attr(out.attr()),
			_ => return req.reply_error(libc::ENOENT),
		};

		out.ttl(TTL);

		req.reply(out)
	}

	fn read(&self, req: &Request, op: op::Read<'_>) -> io::Result<()> {
		match op.ino() {
			HELLO_INO => (),
			ROOT_INO => return req.reply_error(libc::EISDIR),
			_ => return req.reply_error(libc::ENOENT),
		}

		let mut data: &[u8] = &[];

		let offset = op.offset() as usize;
		if offset < HELLO_CONTENT.len() {
			let size = op.size() as usize;
			data = &HELLO_CONTENT[offset..];
			data = &data[..std::cmp::min(data.len(), size)];
		}

		req.reply(data)
	}

	fn dir_entries(&self) -> impl Iterator<Item = (u64, &DirEntry)> + '_ {
		self.entries.iter().enumerate().map(|(i, ent)| {
			let offset = (i + 1) as u64;
			(offset, ent)
		})
	}

	fn readdir(&self, req: &Request, op: op::Readdir<'_>) -> io::Result<()> {
		if op.ino() != ROOT_INO {
			return req.reply_error(libc::ENOTDIR);
		}

		let mut out = ReaddirOut::new(op.size() as usize);

		for (i, entry) in self.dir_entries().skip(op.offset() as usize) {
			let full = out.entry(
				entry.name.as_ref(), //
				entry.ino,
				entry.typ,
				i + 1,
			);
			if full {
				break;
			}
		}

		req.reply(out)
	}

	fn statfs(&self, req: &Request, _op: op::Statfs<'_>) -> io::Result<()> {
		let mut out = StatfsOut::default();

		out.statfs().bsize(512);
		out.statfs().frsize(0);
		out.statfs().blocks(0);
		out.statfs().bfree(0);
		out.statfs().bavail(0);
		out.statfs().files(0);
		out.statfs().ffree(0);
		out.statfs().namelen(255);

		req.reply(out)
	}
}

fn main() -> Result<()> {
	let matches = App::new("archivemount-rs")
		.version(crate_version!())
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

	fs.entries.push(DirEntry {
		name: String::from("."),
		ino: ROOT_INO,
		typ: libc::DT_DIR as u32,

		size: 0,
		blksize: 512,
		blocks: 0,
		atime: Duration::new(0, 0),
		mtime: Duration::new(0, 0),
		ctime: Duration::new(0, 0),
		mode: (libc::S_IFDIR as u32) | 0o555,
		nlink: 2,
		uid: unsafe { libc::getuid() },
		gid: unsafe { libc::getgid() },
		rdev: 0,
	});
	fs.entries.push(DirEntry {
		name: String::from(".."),
		ino: ROOT_INO,
		typ: libc::DT_DIR as u32,

		size: 0,
		blksize: 512,
		blocks: 0,
		atime: Duration::new(0, 0),
		mtime: Duration::new(0, 0),
		ctime: Duration::new(0, 0),
		mode: libc::S_IFDIR as u32 | 0o555,
		nlink: 2,
		uid: unsafe { libc::getuid() },
		gid: unsafe { libc::getgid() },
		rdev: 0,
	});

	let mut ino = 2;
	let mut entry = ArchiveEntry::new();
	let a = match Archive::read_open_filename(&fs.archive_path, 10240, fs.password.as_deref()) {
		Ok(a) => a,
		Err(ArchiveError::Eof) => bail!("EOF"),
		Err(ArchiveError::Retry(s)) => bail!("{}", s),
		Err(ArchiveError::Warn(s)) => bail!("{}", s),
		Err(ArchiveError::Failed(s)) => bail!("{}", s),
		Err(ArchiveError::Fatal(s)) => bail!("{}", s),
		Err(ArchiveError::Unknown(_, s)) => bail!("{}", s),
	};

	loop {
		match a.read_next_header(&mut entry) {
			Ok(()) => {
				let st = entry.stat();
				println!("{}", entry.pathname());
				let kind = match st.st_mode & archive::AE_IFMT {
					archive::AE_IFREG => libc::DT_REG,
					archive::AE_IFLNK => libc::DT_LNK,
					archive::AE_IFSOCK => libc::DT_SOCK,
					archive::AE_IFCHR => libc::DT_CHR,
					archive::AE_IFBLK => libc::DT_BLK,
					archive::AE_IFDIR => libc::DT_DIR,
					archive::AE_IFIFO => libc::DT_FIFO,
					_ => libc::DT_REG,
				};

				let attr = DirEntry {
					name: entry.pathname(),
					ino: ino,
					typ: kind as u32,
					size: st.st_size as u64,
					blksize: 512,
					blocks: ((st.st_size + 511) / 512) as u64,
					atime: Duration::new(st.st_atime as u64, st.st_atime_nsec as u32),
					mtime: Duration::new(st.st_mtime as u64, st.st_mtime_nsec as u32),
					ctime: Duration::new(st.st_ctime as u64, st.st_ctime_nsec as u32),
					mode: st.st_mode,
					nlink: {
						if (kind == libc::DT_DIR) && (st.st_nlink < 2) {
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
				};
				println!("{:?}", attr);
				println!("{}", st.st_mode);
				fs.entries.push(attr);

				ino += 1;
			},
			Err(e) => {
				println!("{:?}", e);
				break;
			}
		}
	}

	let mountpoint = PathBuf::from(matches.value_of("MOUNTPOINT").unwrap());
    ensure!(mountpoint.is_dir(), "MOUNTPOINT must be a directory");

	let mut config = KernelConfig::default();
	if let Some(o) = matches.values_of("o") {
		for option in o {
			config.mount_option(option);
		}
	}

	let session = Session::mount(mountpoint, config)?;

	// Per feature parity con fuse-rs:
	// init (nop)
	// destroy (nop)
	// forget (nop)
	// open (opened(0, 0))
	// release (ok)
	// opendir (opened(0, 0))
	// releasedir (ok)
	// statfs
	while let Some(req) = session.next_request()? {
		match req.operation()? {
			Operation::Lookup(op) => fs.lookup(&req, op)?,
			Operation::Getattr(op) => fs.getattr(&req, op)?,
			Operation::Read(op) => fs.read(&req, op)?,
			Operation::Readdir(op) => fs.readdir(&req, op)?,
			Operation::Statfs(op) => fs.statfs(&req, op)?,
			_ => req.reply_error(libc::ENOSYS)?,
		}
	}

	Ok(())
}

