#! /usr/bin/env fish

set new_version 1.0.0
set new_date (date '+%Y-%m-%d')

sed -i -e "s/^\(\s*version\s*=\s*\).*/\1\"$new_version\"/g" Cargo.toml

sed -i \
	-e "s/^\(\s*:man version:\s*\).*/\1$new_version/g" \
	-e "s/^\(\s*:revdate:\s*\).*/\1$new_date/g" \
	doc/archivefs.1.adoc

