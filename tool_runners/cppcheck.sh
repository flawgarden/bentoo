#!/usr/bin/env bash
set -e

requireCommand() {
  if ! command -v "$1" &> /dev/null
  then
    echo "$1 is required. Please install it and then try again." >&2
    exit 1
  fi
}

requireCommand cppcheck

entry_point=$1

result_filename="cppcheck_out"

cppcheck --enable=all --check-level=exhaustive --template='{file} {line} {column} {cwe}' --output-file="$result_filename" $entry_point >&2

cat "$result_filename"
