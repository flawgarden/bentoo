#!/usr/bin/env bash

entry_point=$1
cd $entry_point

result_filename="codeql-v2.16.5.json"

docker pull ocelaiwo/codeql-java:2.16.5 > /dev/null

docker run --rm -v $(pwd):/benchmark ocelaiwo/codeql-java:2.16.5 sh -c "cd benchmark; /codeql-bundle-linux64/codeql/codeql database create codeql_db --language=java" > /dev/null

docker run --rm -v $(pwd):/benchmark ocelaiwo/codeql-java:2.16.5 sh -c "cd benchmark; /codeql-bundle-linux64/codeql/codeql database analyze codeql_db java-code-scanning.qls --format=sarifv2.1.0 --output=$result_filename" > /dev/null

docker run --rm -v $(pwd):/benchmark ubuntu sh -c "chown $(id -u $USER):$(id -g $USER) -R /benchmark" > /dev/null

result_file="$entry_point/$result_filename"

cat $result_file
