#!/usr/bin/env bash

# Check for install/updates at https://github.com/returntocorp/semgrep

docker pull returntocorp/semgrep > /dev/null

entry_point=$1
cd $entry_point

semgrep_version=$(docker run --rm returntocorp/semgrep semgrep --version)
result_filename="Semgrep-v$semgrep_version.sarif"

docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep --config auto -q --sarif -o "$result_filename" . > /dev/null
docker run --rm -v "${PWD}:/src" ubuntu sh -c "chown $(id -u $USER):$(id -g $USER) -R /src" > /dev/null

result_file="$entry_point/$result_filename"

cat $result_file
