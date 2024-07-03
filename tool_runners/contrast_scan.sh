#!/usr/bin/env bash
set -e

# NOTE: You need to install the tool yourself and then authenticate:
# npm install --location=global @contrast/contrast
# contrast auth

# Contrast scan supports Java, JS and C# only
# For Java, you need to feed it either the .war or the .jar of your project
# This script assumes the .war file is located at entry_point/target/benchmark.war

entry_point=$1
cd $entry_point

contrast scan -f target/benchmark.war --save >&2
cat results.sarif
