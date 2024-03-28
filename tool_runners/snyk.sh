#!/usr/bin/env bash

entry_point=$1
cd $entry_point

result_filename="snyk_output.json"

AUTHORIZED="true"

for OPT in $@; do
  if [[ "$OPT" = *"--not-authorized"* ]]; then
      AUTHORIZED="false"
      shift 1
  fi
done


if [[ "$AUTHORIZED" = "false" ]]; then
  if [[ ! -v SNYK_TOKEN ]]; then
    echo "SNYK_TOKEN is not assigned, so assign it and rerun script again." >> /dev/stderr
    exit 1
  fi
fi

curl https://static.snyk.io/cli/latest/snyk-linux -o snyk > /dev/null
chmod +x ./snyk > /dev/null

./snyk code test --sarif-file-output=$result_filename > /dev/null

result_file="$entry_point/$result_filename"

cat $result_file
