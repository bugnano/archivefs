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
use std::{io, path::PathBuf, time::Duration};

use clap::{Arg, App, crate_version};
use std::os::unix::io::AsRawFd;
use termios::{Termios, tcsetattr, ECHO, TCSANOW};
use std::collections::HashMap;
use std::ffi::OsStr;
use relative_path::RelativePath;

mod archive;

use archive::{Archive, ArchiveEntry, ArchiveError};

const TTL: Duration = Duration::from_secs(60 * 60 * 24 * 365);
const ROOT_INO: u64 = 1;
const HELLO_INO: u64 = 2;
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

	parent: u64,
	entry_name: String,
	symlink: Option<String>,
	hardlink: Option<String>,
	hardlink_target: u64,
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
struct DirContents {
	children: Vec<u64>,
	ino_from_name: HashMap<String, u64>,
}

impl DirContents {
	fn new() -> DirContents {
		DirContents {
			children: Vec::new(),
			ino_from_name: HashMap::new(),
		}
	}
}

#[derive(Debug)]
struct ArchiveFS {
	archive_path: String,
	password: Option<String>,
	inodes: HashMap<u64, DirEntry>,
	directories: HashMap<u64, DirContents>,
}

impl ArchiveFS {
	fn hardlink_ino(&self, ino: u64) -> u64 {
		if !self.inodes.contains_key(&ino) {
			return ino;
		}

		let mut target_ino = ino;

		while self.inodes[&target_ino].hardlink_target != 0 {
			target_ino = self.inodes[&target_ino].hardlink_target;
		}

		target_ino
	}

	fn lookup(&self, req: &Request, op: op::Lookup<'_>) -> io::Result<()> {
		let parent = op.parent();

		if self.directories.contains_key(&parent) {
			if let Some(&ino) = self.directories[&parent].ino_from_name.get(&op.name().to_string_lossy().into_owned()) {
				let mut out = EntryOut::default();

				let target_ino = self.hardlink_ino(ino);

				self.inodes[&target_ino].fill_attr(out.attr());
				out.ino(target_ino);
				out.ttl_attr(TTL);
				out.ttl_entry(TTL);

				req.reply(out)
			} else {
				req.reply_error(libc::ENOENT)
			}
		} else {
			req.reply_error(libc::ENOENT)
		}
	}

	fn getattr(&self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
		let mut out = AttrOut::default();

		if let Some(entry) = self.inodes.get(&self.hardlink_ino(op.ino())) {
			entry.fill_attr(out.attr());
			out.ttl(TTL);

			req.reply(out)
		} else {
			req.reply_error(libc::ENOENT)
		}
	}

	fn readlink(&self, req: &Request, op: op::Readlink<'_>) -> io::Result<()> {
		if let Some(entry) = self.inodes.get(&self.hardlink_ino(op.ino())) {
			if let Some(symlink) = &entry.symlink {
				req.reply(&symlink)
			} else {
				req.reply_error(libc::EINVAL)
			}
		} else {
			req.reply_error(libc::ENOENT)
		}
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

	fn readdir(&self, req: &Request, op: op::Readdir<'_>) -> io::Result<()> {
		let ino = self.hardlink_ino(op.ino());
		let offset = op.offset();

		if !self.directories.contains_key(&ino) {
			return req.reply_error(libc::ENOTDIR);
		}

		let mut out = ReaddirOut::new(op.size() as usize);

		let mut entry = &self.inodes[&ino];

		if offset < 1 {
			out.entry(
				OsStr::new("."),
				ino,
				entry.typ,
				1,
			);
		}

		if offset < 2 {
			entry = &self.inodes[&self.hardlink_ino(entry.parent)];

			out.entry(
				OsStr::new(".."),
				entry.ino,
				entry.typ,
				2,
			);
		}

		for (i, &child_ino) in self.directories[&ino].children.iter().enumerate().skip(offset.saturating_sub(2) as usize) {
			entry = &self.inodes[&self.hardlink_ino(child_ino)];
			let real_entry = &self.inodes[&child_ino];

			let full = out.entry(
				OsStr::new(&real_entry.name),
				entry.ino,
				entry.typ,
				(i + 3) as u64,
			);

			if full {
				break;
			}
		}

		req.reply(out)
	}

	fn statfs(&self, req: &Request, _op: op::Statfs<'_>) -> io::Result<()> {
		let mut out = StatfsOut::default();
		let out_statfs = out.statfs();

		out_statfs.bsize(512);
		out_statfs.frsize(0);
		out_statfs.blocks(0);
		out_statfs.bfree(0);
		out_statfs.bavail(0);
		out_statfs.files(0);
		out_statfs.ffree(0);
		out_statfs.namelen(255);

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
		inodes: HashMap::new(),
		directories: HashMap::new(),
	};

	fs.inodes.insert(ROOT_INO, DirEntry {
		name: String::from(""),
		ino: ROOT_INO,
		typ: libc::DT_DIR as u32,

		size: 0,
		blksize: 512,
		blocks: 0,
		atime: Duration::new(0, 0),
		mtime: Duration::new(0, 0),
		ctime: Duration::new(0, 0),
		mode: libc::S_IFDIR | 0o555,
		nlink: 2,
		uid: unsafe { libc::getuid() },
		gid: unsafe { libc::getgid() },
		rdev: 0,

		parent: ROOT_INO,
		entry_name: String::from("/"),
		symlink: None,
		hardlink: None,
		hardlink_target: 0,
	});

	let mut counter: u64 = 2;
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

	let mut ino_from_dir: HashMap<String, u64> = HashMap::new();
	let mut ino_from_entry_name: HashMap<String, u64> = HashMap::new();
	let mut hardlinks: Vec<u64> = Vec::new();

	while let Ok(_) = a.read_next_header(&mut entry) {
		let entry_name = entry.pathname().unwrap_or(String::from(""));
		let full_name = String::from(RelativePath::new(&entry_name).normalize().to_string().trim_start_matches("../"));

		if full_name.is_empty() {
			continue;
		}

		let st = entry.stat();
		let typ = match st.st_mode & archive::AE_IFMT {
			archive::AE_IFREG => libc::DT_REG,
			archive::AE_IFLNK => libc::DT_LNK,
			archive::AE_IFSOCK => libc::DT_SOCK,
			archive::AE_IFCHR => libc::DT_CHR,
			archive::AE_IFBLK => libc::DT_BLK,
			archive::AE_IFDIR => libc::DT_DIR,
			archive::AE_IFIFO => libc::DT_FIFO,
			_ => libc::DT_UNKNOWN,
		};

		let name: &str;
		let parent: u64;
		if let Some(pos) = full_name.rfind('/') {
			let (parent_name, basename) = full_name.split_at(pos);

			name = &basename[1..];

			if let Some(&parent_ino) = ino_from_dir.get(parent_name) {
				parent = parent_ino;
			} else {
				ino_from_dir.insert(String::from(parent_name), counter);
				parent = counter;
				counter += 1;
			}
		} else {
			name = &full_name;
			parent = ROOT_INO;
		}

		let ino: u64;
		if typ == libc::DT_DIR {
			if ino_from_dir.contains_key(&full_name) {
				ino = ino_from_dir[&full_name];
			} else {
				ino_from_dir.insert(String::from(&full_name), counter);
				ino = counter;
				counter += 1;
			}
		} else {
			ino = counter;
			counter += 1;
		}

		let dir_contents = fs.directories.entry(parent).or_insert(DirContents::new());
		dir_contents.children.push(ino);
		dir_contents.ino_from_name.insert(String::from(name), ino);

		ino_from_entry_name.insert(String::from(&entry_name), ino);

		let attr = DirEntry {
			name: String::from(name),
			ino: ino,
			typ: typ as u32,

			size: st.st_size as u64,
			blksize: 512,
			blocks: ((st.st_size + 511) / 512) as u64,
			atime: Duration::new(st.st_atime as u64, st.st_atime_nsec as u32),
			mtime: Duration::new(st.st_mtime as u64, st.st_mtime_nsec as u32),
			ctime: Duration::new(st.st_ctime as u64, st.st_ctime_nsec as u32),
			mode: st.st_mode,
			nlink: {
				if (typ == libc::DT_DIR) && (st.st_nlink < 2) {
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

			parent: parent,
			entry_name: entry_name,
			symlink: entry.symlink(),
			hardlink: entry.hardlink(),
			hardlink_target: 0,
		};

		if attr.hardlink.is_some() {
			hardlinks.push(ino);
		}

		println!("{:?}", attr);
		fs.inodes.insert(ino, attr);
	}

	for ino in hardlinks {
		if let Some(entry) = fs.inodes.get_mut(&ino) {
			if let Some(hardlink) = &entry.hardlink {
				if let Some(&target_ino) = ino_from_entry_name.get(hardlink) {
					entry.hardlink_target = target_ino;
				}
			}
		}
	}

	println!("fs.directories: {:?}", fs.directories);
	println!("ino_from_dir: {:?}", ino_from_dir);

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
			Operation::Readlink(op) => fs.readlink(&req, op)?,
			Operation::Read(op) => fs.read(&req, op)?,
			Operation::Readdir(op) => fs.readdir(&req, op)?,
			Operation::Statfs(op) => fs.statfs(&req, op)?,
			_ => req.reply_error(libc::ENOSYS)?,
		}
	}

	Ok(())
}

