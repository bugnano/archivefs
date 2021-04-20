# archivefs

Archivefs is a read-only FUSE filesystem for mounting compressed archives,
inspired by archivemount.


## Features

* Read-only mount any archive file supported by libarchive to a directory
* Several orders of magnitude faster decompression compared to archivemount

### Archive formats

Archivefs supports all the formats supported by libarchive, including, but
not limited to:

* tar (compressed with gzip, bzip2, xz, zstd)
* cpio
* ISO9660 (including Joliet and Rockridge extensions)
* zip
* 7-Zip

Note that libarchive has known bugs when reading rar archives.

## System requirements

### For running

* Linux Kernel 3.15 or later (While FUSE works on other operating systems, the
  polyfuse crate used by archivefs only supports Linux at the moment)
* The `fusermount` command (usually provided by the `fuse` or `fuse2` package)
* libarchive

### For compiling

* Rust 1.31 or greater
* Development files for libarchive (usually provided by the `libarchive-dev`
  or `libarchive-devel` package)

### For building the man page

* Python 3.5 or greater
* AsciiDoc

## Installation

```bash
# This will install only the archivefs executable in $HOME/.cargo/bin, without any
# man page. Also, make sure that the $HOME/.cargo/bin directory is in your PATH
cargo install archivefs

# Alternatively, you can build from source using the command
cargo build --release
# and then copy the file target/release/archivefs somewhere in your PATH

# To build the man page:
a2x -f manpage doc/archivefs.1.adoc
# and then copy the file doc/archivefs.1 in a man path (like $HOME/.local/share/man/man1 )
```

## Usage

```bash
archivefs [OPTIONS] ARCHIVEPATH MOUNTPOINT
```

### Example session

Consider the gzipped tar archive `files.tgz` containing files `file1` and
`file2`, and an empty directory `mnt`.

```bash
$ ls
files.tgz    mnt/

# Mount the archive file
$ archivefs files.tgz mnt

$ ls mnt
file1    file2

# Perform desired read operations on the archive via mnt/
# For example, to extract a file simply copy it
$ cp mnt/file1 ~/

# Unmount the archive when done
$ umount mnt
```

## Write support

Contrary to archivemount, which sort-of supports writing to an archive by
recreating it, archivefs only supports reading from archives.

## Hard link support

Note that if an archive contains hard links, they will be treated as separate
files by archivefs.

