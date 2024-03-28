#!/usr/bin/env bash

# Check for install/updates at https://github.com/insidersec/insider

insider_version=3.0.0 # We use docker tag 3.0.0, for some reason insider's -version option does something weird

entry_point=$1
cd $entry_point

result_filename="insider-v$insider_version.json"

docker run --entrypoint /bin/sh --rm -v $entry_point:/target-project insidersec/insider:3.0.0 -c "./insider -tech java -exclude '.idea' -exclude '.mvn' -exclude 'results' -exclude 'scorecard' -exclude 'scripts' -exclude 'tools' -target /target-project; cp report.json /target-project/$result_filename" > /dev/null

docker run --rm -v "${PWD}:/src" ubuntu sh -c "chown $(id -u $USER):$(id -g $USER) -R /src" > /dev/null

result_file="$entry_point/$result_filename"

cat $result_file
