#!/usr/bin/env bash

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
root_dir="$( cd $script_dir/.. && pwd )"

files=(
    "summary.json"
)

files_14=(
    "CodeQL_Default.err"
    "CodeQL_Default.out"
    "CodeQL_Default.metadata"
    "Insider_Default.json"
    "Insider_Default.sarif"
    "Insider_Default.err"
    "Insider_Default.out"
    "Insider_Default.metadata"
    "Semgrep_Default.json"
    "Semgrep_Default.sarif"
    "Semgrep_Default.err"
    "Semgrep_Default.out"
    "Semgrep_Default.metadata"
    "SonarQube_Default.json"
    "SonarQube_Default.sarif"
    "SonarQube_Default.err"
    "SonarQube_Default.out"
    "SonarQube_Default.metadata"
    "truth.sarif"
)

files_16=(
    "CodeQL_Default.json"
    "CodeQL_Default.sarif"
    "CodeQL_Default.err"
    "CodeQL_Default.out"
    "CodeQL_Default.metadata"
    "Insider_Default.json"
    "Insider_Default.sarif"
    "Insider_Default.err"
    "Insider_Default.out"
    "Insider_Default.metadata"
    "Semgrep_Default.json"
    "Semgrep_Default.sarif"
    "Semgrep_Default.err"
    "Semgrep_Default.out"
    "Semgrep_Default.metadata"
    "SonarQube_Default.json"
    "SonarQube_Default.sarif"
    "SonarQube_Default.err"
    "SonarQube_Default.out"
    "SonarQube_Default.metadata"
    "truth.sarif"
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

bentoo template --tools tool_runners/tools.toml playground/play/benchmark > playground/play/benchmark/runs.toml
bentoo bench --tools tool_runners/tools.toml --runs playground/play/benchmark/runs.toml playground/play/output

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
