#!/usr/bin/env bash

requireCommand() {
	if ! command -v "$1" &>/dev/null; then
		echo "$1 is required. Please install it and then try again." >&2
		exit 1
	fi
}

requireCommand go

set -e

entry_point=$1

seqra_dir="$HOME/.bentoo/seqra"
seqra_bin="$(go env GOPATH)/bin/seqra"

if [ ! -f "$seqra_bin" ]; then
	echo "Installing seqra..." >&2
	go install github.com/seqra/seqra/v2@latest >&2
fi

if [ ! -f "$seqra_dir/.pulled" ]; then
	echo "Running seqra pull (downloading analyzer, rules, Java runtime)..." >&2
	mkdir -p "$seqra_dir" >&2
	"$seqra_bin" pull >&2
	touch "$seqra_dir/.pulled"
else
	echo "Using cached seqra installation" >&2
fi

cd "$entry_point"
result_filename="seqra.sarif"

"$seqra_bin" scan --output "$result_filename" . >&2

cat "$result_filename"
