#!/usr/bin/env bash

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
root_dir="$( cd $script_dir/.. && pwd )"

files=(
    "summary.json"
)

files_14=(
    "CodeQL_Java.err"
    "CodeQL_Java.out"
    "CodeQL_Java.metadata"
    "Insider_Java.json"
    "Insider_Java.sarif"
    "Insider_Java.err"
    "Insider_Java.out"
    "Insider_Java.metadata"
    "Semgrep_Java.json"
    "Semgrep_Java.sarif"
    "Semgrep_Java.err"
    "Semgrep_Java.out"
    "Semgrep_Java.metadata"
    "SonarQube_Java.json"
    "SonarQube_Java.sarif"
    "SonarQube_Java.err"
    "SonarQube_Java.out"
    "SonarQube_Java.metadata"
    "Bearer_Java.json"
    "Bearer_Java.sarif"
    "Bearer_Java.err"
    "Bearer_Java.out"
    "Bearer_Java.metadata"
    "Snyk_Java.json"
    "Snyk_Java.sarif"
    "Snyk_Java.err"
    "Snyk_Java.out"
    "Snyk_Java.metadata"
    "truth.sarif"
    "summary.json"
)

files_16=(
    "CodeQL_Java.json"
    "CodeQL_Java.sarif"
    "CodeQL_Java.err"
    "CodeQL_Java.out"
    "CodeQL_Java.metadata"
    "Insider_Java.json"
    "Insider_Java.sarif"
    "Insider_Java.err"
    "Insider_Java.out"
    "Insider_Java.metadata"
    "Semgrep_Java.json"
    "Semgrep_Java.sarif"
    "Semgrep_Java.err"
    "Semgrep_Java.out"
    "Semgrep_Java.metadata"
    "SonarQube_Java.json"
    "SonarQube_Java.sarif"
    "SonarQube_Java.err"
    "SonarQube_Java.out"
    "SonarQube_Java.metadata"
    "Bearer_Java.json"
    "Bearer_Java.sarif"
    "Bearer_Java.err"
    "Bearer_Java.out"
    "Bearer_Java.metadata"
    "Snyk_Java.json"
    "Snyk_Java.sarif"
    "Snyk_Java.err"
    "Snyk_Java.out"
    "Snyk_Java.metadata"
    "truth.sarif"
    "summary.json"
)

cd $root_dir

rm -rf playground/play

# reference run artifacts will be stored there
mkdir -p playground/play

cd playground/play

# prepare vulnerable and fixed versions of example project
wget "https://github.com/codehaus-plexus/plexus-utils/archive/refs/tags/plexus-utils-3.0.14.tar.gz"
wget "https://github.com/codehaus-plexus/plexus-utils/archive/refs/tags/plexus-utils-3.0.16.tar.gz"

mkdir -p plexus-utils-3.0.14
mkdir -p plexus-utils-3.0.16

tar -xf plexus-utils-3.0.14.tar.gz -C plexus-utils-3.0.14 --strip-components=1
tar -xf plexus-utils-3.0.16.tar.gz -C plexus-utils-3.0.16 --strip-components=1

cp ../reference_truths/truth_3.0.14_CVE-2017-1000487.sarif plexus-utils-3.0.14/truth.sarif
cp ../reference_truths/truth_3.0.16_CVE-2017-1000487.sarif plexus-utils-3.0.16/truth.sarif

mkdir -p benchmark
mv plexus-utils-3.0.14 benchmark/plexus-utils-3.0.14
mv plexus-utils-3.0.16 benchmark/plexus-utils-3.0.16

cd $root_dir

cargo build

export PATH="$(pwd)/target/debug:$PATH"

bentoo template --tools tool_runners/tools_java.toml playground/play/benchmark > playground/play/benchmark/runs.toml
bentoo bench --tools tool_runners/tools_java.toml --runs playground/play/benchmark/runs.toml playground/play/output

cd $root_dir
cd playground/play/output

for file in "${files[@]}"; do
    if [[ ! -f $file ]]; then
        echo "File $(pwd)/$file not found";
        exit 1
    fi
done

cd $root_dir
cd playground/play/output/plexus-utils-3.0.14

for file in "${files_14[@]}"; do
    if [[ ! -f $file ]]; then
        echo "File $(pwd)/$file not found";
        exit 1
    fi
done

cd $root_dir
cd playground/play/output/plexus-utils-3.0.16

for file in "${files_16[@]}"; do
    if [[ ! -f $file ]]; then
        echo "File $(pwd)/$file not found";
        exit 1
    fi
done
