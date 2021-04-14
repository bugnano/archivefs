# archivefs

Archivefs is a read-only FUSE filesystem for mounting compressed archives,
inspired by archivemount.


## Features

* Read-only mount any archive file supported by libarchive to a directory
* Several orders of magnitude faster decompression compared to archivemount

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

## Installation

```bash
cargo install archivefs
```

## Usage

```bash
archivefs [OPTIONS] <ARCHIVEPATH> <MOUNTPOINT>
```

Options are the normal fuse mount options, nothing special supported yet.

## Write support

Contrary to archivemount, which sort-of supports writing to an archive by
recreating it, archivefs only supports reading from archives.

