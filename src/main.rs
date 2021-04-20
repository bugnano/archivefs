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
	reply::{AttrOut, EntryOut, FileAttr, OpenOut, ReaddirOut, StatfsOut},
	KernelConfig, Operation, Request, Session,
};

use anyhow::{bail, ensure, Result};
use std::{io, path::PathBuf, time::Duration};

use clap::{Arg, App, crate_name, crate_version};
use std::os::unix::io::AsRawFd;
use termios::{Termios, tcsetattr, ECHO, TCSANOW};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use relative_path::RelativePath;
use log::{LevelFilter, debug, trace};
use env_logger::{Builder, WriteStyle};
use std::io::Write;
use daemonize::Daemonize;

mod archive;

use archive::{Archive, ArchiveEntry};

const TTL: Duration = Duration::from_secs(60 * 60 * 24 * 365);
const ROOT_INO: u64 = 1;

const BLOCK_SIZE: usize = 10240;

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
struct OpenedArchive {
	entry_name: String,
	archive: Archive,
	position: usize,
}

#[derive(Debug)]
struct ArchiveFS {
	archive_path: String,
	password: Option<String>,
	inodes: HashMap<u64, DirEntry>,
	directories: HashMap<u64, DirContents>,
	counter: u64,
	opened_files: HashMap<u64, OpenedArchive>,
	buf_discard: Vec<u8>,
}

impl ArchiveFS {
	fn lookup(&self, req: &Request, op: op::Lookup<'_>) -> io::Result<()> {
		trace!("lookup()");

		let parent = op.parent();
		let name = op.name().to_string_lossy().into_owned();

		trace!("parent = {}", parent);
		trace!("name = {}", name);

		if self.directories.contains_key(&parent) {
			if let Some(&ino) = self.directories[&parent].ino_from_name.get(&name) {
				let mut out = EntryOut::default();

				self.inodes[&ino].fill_attr(out.attr());
				out.ino(ino);
				out.ttl_attr(TTL);
				out.ttl_entry(TTL);

				trace!("OK");
				req.reply(out)
			} else {
				trace!("ENOENT: name not in directory");
				req.reply_error(libc::ENOENT)
			}
		} else {
			trace!("ENOENT: parent not in self.directories");
			req.reply_error(libc::ENOENT)
		}
	}

	fn getattr(&self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
		trace!("getattr()");

		let ino = op.ino();

		trace!("ino = {}", ino);

		let mut out = AttrOut::default();

		if let Some(entry) = self.inodes.get(&ino) {
			entry.fill_attr(out.attr());
			out.ttl(TTL);

			trace!("OK");
			req.reply(out)
		} else {
			trace!("ENOENT: ino not in self.inodes");
			req.reply_error(libc::ENOENT)
		}
	}

	fn readlink(&self, req: &Request, op: op::Readlink<'_>) -> io::Result<()> {
		trace!("readlink()");

		let ino = op.ino();

		trace!("ino = {}", ino);

		if let Some(entry) = self.inodes.get(&ino) {
			if let Some(symlink) = &entry.symlink {
				trace!("OK");
				req.reply(&symlink)
			} else {
				trace!("EINVAL: entry.symlink is None");
				req.reply_error(libc::EINVAL)
			}
		} else {
			trace!("ENOENT: ino not in self.inodes");
			req.reply_error(libc::ENOENT)
		}
	}

	fn open(&mut self, req: &Request, op: op::Open<'_>) -> io::Result<()> {
		trace!("open()");

		let ino = op.ino();

		trace!("ino = {}", ino);

		if ((op.flags() as i32) & libc::O_ACCMODE) != libc::O_RDONLY {
			trace!("EACCES: flags != O_RDONLY");
			return req.reply_error(libc::EACCES);
		} else if self.directories.contains_key(&ino) {
			trace!("EISDIR: ino in self.directories");
			return req.reply_error(libc::EISDIR);
		} else if !self.inodes.contains_key(&ino) {
			trace!("ENOENT: ino not in self.inodes");
			return req.reply_error(libc::ENOENT);
		} else {
			let mut entry = ArchiveEntry::new();
			let a = match Archive::read_open_filename(&self.archive_path, BLOCK_SIZE, self.password.as_deref()) {
				Ok(a) => a,
				Err(e) => {
					trace!("ERROR (read_open_filename): {}", e);
					return req.reply_error(e.errno);
				},
			};

			let target_name = &self.inodes[&ino].entry_name;

			while let Ok(_) = a.read_next_header(&mut entry) {
				let entry_name = entry.pathname().unwrap_or(String::from(""));
				if &entry_name == target_name {
					let fh = self.counter;
					self.counter += 1;

					trace!("fh = {}", fh);

					self.opened_files.insert(fh, OpenedArchive {
						entry_name: String::from(target_name),
						archive: a,
						position: 0,
					});

					let mut out = OpenOut::default();

					out.fh(fh);
					out.keep_cache(true);

					trace!("OK");
					return req.reply(out);
				}
			}

			trace!("ENOENT: entry_name not found in archive");
			req.reply_error(libc::ENOENT)
		}
	}

	fn read(&mut self, req: &Request, op: op::Read<'_>) -> io::Result<()> {
		trace!("read()");

		let fh = op.fh();
		let offset = op.offset() as usize;
		let size = op.size() as usize;

		trace!("fh = {}", fh);
		trace!("offset = {}", offset);
		trace!("size = {}", size);

		if let Some(archive) = self.opened_files.get_mut(&fh) {
			if size == 0 {
				trace!("OK (size == 0)");
				return req.reply(&[]);
			}

			trace!("archive.position = {}", archive.position);

			if offset < archive.position {
				// The requested offset is lower than the current position:
				// We have to close the current archive, open a new one and seek until the offset
				trace!("offset < archive.position");
				let mut entry = ArchiveEntry::new();
				let a = match Archive::read_open_filename(&self.archive_path, BLOCK_SIZE, self.password.as_deref()) {
					Ok(a) => a,
					Err(e) => {
						trace!("ERROR (read_open_filename): {}", e);
						return req.reply_error(e.errno);
					},
				};

				let mut found = false;
				while let Ok(_) = a.read_next_header(&mut entry) {
					let entry_name = entry.pathname().unwrap_or(String::from(""));
					if entry_name == archive.entry_name {
						found = true;

						archive.archive = a;
						archive.position = 0;
						break;
					}
				}

				if !found {
					trace!("ENOENT: entry_name not found in archive");
					return req.reply_error(libc::ENOENT);
				}
			}

			if offset > archive.position {
				trace!("offset > archive.position");
				// The requested offset is greater than the current position:
				// Read and discard until we get to the correct offset
				let mut bytes_remaining = offset - archive.position;

				while bytes_remaining > self.buf_discard.len() {
					match archive.archive.read_data(&mut self.buf_discard) {
						Ok(bytes_read) => {
							bytes_remaining -= bytes_read;
							archive.position += bytes_read;

							// If we read 0, then we reached the end of file
							if bytes_read == 0 {
								trace!("OK ([1] reached end of file)");
								return req.reply(&[]);
							}
						},
						Err(e) => {
							trace!("ERROR ([1] archive.read_data): {}", e);
							return req.reply_error(e.errno);
						},
					}
				}

				while bytes_remaining > 0 {
					match archive.archive.read_data(&mut self.buf_discard[..bytes_remaining]) {
						Ok(bytes_read) => {
							bytes_remaining -= bytes_read;
							archive.position += bytes_read;

							// If we read 0, then we reached the end of file
							if bytes_read == 0 {
								trace!("OK ([2] reached end of file)");
								return req.reply(&[]);
							}
						},
						Err(e) => {
							trace!("ERROR ([2] archive.read_data): {}", e);
							return req.reply_error(e.errno);
						},
					}
				}
			}

			let mut data: Vec<u8> = vec![0; size];
			let mut total_bytes: usize = 0;

			while total_bytes < size {
				match archive.archive.read_data(&mut data[total_bytes..]) {
					Ok(bytes_read) => {
						total_bytes += bytes_read;
						archive.position += bytes_read;

						// If we read 0, then we reached the end of file
						if bytes_read == 0 {
							trace!("OK ([3] reached end of file)");
							return req.reply(&data[..total_bytes]);
						}
					},
					Err(e) => {
						trace!("ERROR ([3] archive.read_data): {}", e);
						return req.reply_error(e.errno);
					},
				}
			}

			trace!("OK");
			req.reply(data)
		} else {
			trace!("ENOENT: fh not in self.opened_files");
			req.reply_error(libc::ENOENT)
		}
	}

	fn release(&mut self, req: &Request, op: op::Release<'_>) -> io::Result<()> {
		trace!("release()");

		let fh = op.fh();

		trace!("fh = {}", fh);

		let _file = self.opened_files.remove(&fh);

		trace!("OK");
		req.reply(())
	}

	fn readdir(&self, req: &Request, op: op::Readdir<'_>) -> io::Result<()> {
		trace!("readdir()");

		let ino = op.ino();
		let offset = op.offset();

		trace!("ino = {}", ino);
		trace!("offset = {}", offset);

		if !self.directories.contains_key(&ino) {
			trace!("ENOTDIR: ino not in self.directories");
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
			entry = &self.inodes[&entry.parent];

			out.entry(
				OsStr::new(".."),
				entry.ino,
				entry.typ,
				2,
			);
		}

		for (i, &child_ino) in self.directories[&ino].children.iter().enumerate().skip(offset.saturating_sub(2) as usize) {
			entry = &self.inodes[&child_ino];

			let full = out.entry(
				OsStr::new(&entry.name),
				entry.ino,
				entry.typ,
				(i + 3) as u64,
			);

			if full {
				break;
			}
		}

		trace!("OK");
		req.reply(out)
	}

	fn statfs(&self, req: &Request, _op: op::Statfs<'_>) -> io::Result<()> {
		trace!("statfs()");

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

		trace!("OK");
		req.reply(out)
	}
}

fn populate_filesystem(fs: &mut ArchiveFS) -> Result<()>  {
	let uid = unsafe { libc::geteuid() };
	let gid = unsafe { libc::getegid() };
	let mask = unsafe { libc::umask(0) };
	unsafe { libc::umask(mask) };

	// Inode number 1 is the root directory
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
		mode: libc::S_IFDIR | (0o777 & !mask),
		nlink: 2,
		uid: uid,
		gid: gid,
		rdev: 0,

		parent: ROOT_INO,
		entry_name: String::from(""),
		symlink: None,
	});

	fs.directories.insert(ROOT_INO, DirContents::new());

	// File inode numbers start from 2
	let mut counter: u64 = 2;

	let mut entry = ArchiveEntry::new();
	let a = match Archive::read_open_filename(&fs.archive_path, BLOCK_SIZE, fs.password.as_deref()) {
		Ok(a) => a,
		Err(e) => bail!("{}", e.error_string),
	};

	// Some temporary data structures to speed up file name/inode lookup
	#[derive(Debug)]
	struct HardLink {
		entry_name: String,
		target: u64,
	}

	let mut ino_from_dir: HashMap<String, u64> = HashMap::new();
	let mut ino_from_entry_name: HashMap<String, u64> = HashMap::new();
	let mut hardlinks: HashMap<u64, HardLink> = HashMap::new();

	// Let's populate the filesystem
	while let Ok(_) = a.read_next_header(&mut entry) {
		let entry_name = entry.pathname().unwrap_or(String::from(""));
		let full_name = String::from(RelativePath::new(&entry_name).normalize().to_string().trim_start_matches("../"));

		// full_name can be empty if it refers to the root directory
		if full_name.is_empty() || (full_name == "..") {
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

		// Get directory and file name
		let name: &str;
		let mut parent = ROOT_INO;
		if let Some(pos) = full_name.rfind('/') {
			name = &full_name[pos+1..];

			for i_parent in full_name.match_indices('/') {
				let parent_name = &full_name[..i_parent.0];

				if let Some(&parent_ino) = ino_from_dir.get(parent_name) {
					parent = parent_ino;
				} else {
					// This file refers to a directory that has not yet been listed in the archive
					// Create the entry with a default value that will be changed if it will appear
					// in a later read_next_header call
					let temp_name = {
						if let Some(pos) = parent_name.rfind('/') {
							&parent_name[pos+1..]
						} else {
							parent_name
						}
					};

					ino_from_dir.insert(String::from(parent_name), counter);
					fs.directories.insert(counter, DirContents::new());

					let dir_contents = fs.directories.get_mut(&parent).unwrap();
					dir_contents.children.push(counter);
					dir_contents.ino_from_name.insert(String::from(temp_name), counter);

					fs.inodes.insert(counter, DirEntry {
						name: String::from(temp_name),
						ino: counter,
						typ: libc::DT_DIR as u32,

						size: 0,
						blksize: 512,
						blocks: 0,
						atime: Duration::new(0, 0),
						mtime: Duration::new(0, 0),
						ctime: Duration::new(0, 0),
						mode: libc::S_IFDIR | (0o777 & !mask),
						nlink: 2,
						uid: uid,
						gid: gid,
						rdev: 0,

						parent: parent,
						entry_name: String::from(""),
						symlink: None,
					});

					parent = counter;
					counter += 1;
				}
			}
		} else {
			name = &full_name;
			parent = ROOT_INO;
		}

		let ino: u64;
		if typ == libc::DT_DIR {
			if ino_from_dir.contains_key(&full_name) {
				// This directory has already been referenced previously by a file
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
		if !dir_contents.children.contains(&ino) {
			dir_contents.children.push(ino);
			dir_contents.ino_from_name.insert(String::from(name), ino);
		}

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
		};

		// Hardlinks don't have a correct stat(), so they have to be processed later
		if let Some(hardlink) = entry.hardlink() {
			hardlinks.insert(ino, HardLink {
				entry_name: hardlink,
				target: ino,
			});
		}

		debug!("{:?}", attr);
		fs.inodes.insert(ino, attr);
	}

	// Step 1: Get the target inode number for hard links
	debug!("Hardlinks");
	for (_ino, hardlink) in hardlinks.iter_mut() {
		if let Some(&target_ino) = ino_from_entry_name.get(&hardlink.entry_name) {
			hardlink.target = target_ino;
		}
	}

	// Step 2: Recurse into the target inode until we find a real file
	for (&ino, hardlink) in hardlinks.iter() {
		let mut target_ino = hardlink.target;

		// Maintain a set of visited targets to prevent infinite loops
		let mut visited_targets: HashSet<u64> = HashSet::new();
		visited_targets.insert(ino);
		while hardlinks.contains_key(&target_ino) && (!visited_targets.contains(&hardlinks[&target_ino].target))  {
			target_ino = hardlinks[&target_ino].target;
			visited_targets.insert(target_ino);
		}

		let entry = &fs.inodes[&ino];
		let target_entry = &fs.inodes[&target_ino];

		// Create a new entry to replace the hard link
		let attr = DirEntry {
			name: String::from(&entry.name),
			ino: ino,
			typ: target_entry.typ,

			size: target_entry.size,
			blksize: target_entry.blksize,
			blocks: target_entry.blocks,
			atime: target_entry.atime,
			mtime: target_entry.mtime,
			ctime: target_entry.ctime,
			mode: target_entry.mode,
			nlink: target_entry.nlink,
			uid: target_entry.uid,
			gid: target_entry.gid,
			rdev: target_entry.rdev,

			parent: entry.parent,
			entry_name: String::from(&target_entry.entry_name),
			symlink: match &target_entry.symlink {
				Some(symlink) => Some(String::from(symlink)),
				None => None,
			},
		};

		debug!("{:?}", attr);
		fs.inodes.insert(ino, attr);
	}

	debug!("fs.directories: {:?}", fs.directories);
	debug!("ino_from_dir: {:?}", ino_from_dir);

	Ok(())
}

fn main() -> Result<()> {
	let matches = App::new(crate_name!())
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
		.arg(Arg::with_name("foreground")
			.short("f")
			.long("foreground")
			.help("Foreground operation"))
		.arg(Arg::with_name("debug")
			.short("d")
			.long("debug")
			.multiple(true)
			.help("Enable debug output (implies -f, specify more than once for trace output)"))
		.arg(Arg::with_name("o")
			.short("o")
			.multiple(true)
			.takes_value(true)
			.number_of_values(1)
			.value_name("OPTION")
			.help("FUSE mount option"))
		.get_matches();

	// Configure logging as soon as possible
	Builder::new()
		.format(|buf, record| writeln!(buf, "{}", record.args()))
		.filter(None, match matches.occurrences_of("debug") {
			0 => LevelFilter::Off,
			1 => LevelFilter::Debug,
			_ => LevelFilter::Trace,
		})
		.write_style(WriteStyle::Auto)
		.init();

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
		counter: 1,
		opened_files: HashMap::new(),
		buf_discard: vec![0; BLOCK_SIZE],
	};

	let mountpoint = PathBuf::from(matches.value_of("MOUNTPOINT").unwrap());
    ensure!(mountpoint.is_dir(), "MOUNTPOINT must be a directory");

	populate_filesystem(&mut fs)?;

	let mut config = KernelConfig::default();
	if let Some(o) = matches.values_of("o") {
		for option in o {
			config.mount_option(option);
		}
	}

	config.mount_option("ro");
	config.mount_option("fsname=archivefs");

	let session = Session::mount(mountpoint, config)?;

	// Run as a daemon unless foreground operation or debug output is requested
	if !(matches.is_present("foreground") || matches.is_present("debug")) {
		Daemonize::new()
			.working_directory(std::env::current_dir()?)
			.start()?;
	}

	while let Some(req) = session.next_request()? {
		match req.operation()? {
			Operation::Lookup(op) => fs.lookup(&req, op)?,
			Operation::Getattr(op) => fs.getattr(&req, op)?,
			Operation::Readlink(op) => fs.readlink(&req, op)?,
			Operation::Open(op) => fs.open(&req, op)?,
			Operation::Read(op) => fs.read(&req, op)?,
			Operation::Release(op) => fs.release(&req, op)?,
			Operation::Readdir(op) => fs.readdir(&req, op)?,
			Operation::Statfs(op) => fs.statfs(&req, op)?,
			_ => req.reply_error(libc::ENOSYS)?,
		}
	}

	Ok(())
}

