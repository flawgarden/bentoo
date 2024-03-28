# Getting started

This guide demonstrates how to start using `bentoo` with your tools and benchmark suites.
(If you want an example to follow along, take a look at step 0. Otherwise, continue reading at step 1.)

## 0. Run the `reference_run.sh` script

This guide relies on examples generated when executing `playground/reference_run.sh`. This script fetches two versions (vulnerable and fixed) of the same project
from the internet, provides them with respective `truth.sarif` files and then uses docker to run two reference tools (`Insider` and `CodeQL`) on them.

After you run this script, you will have the `playground/play` directory populated with the generated benchmark suite and run results. This directory will be refered
to as the *example* throughout the guide.

## 1. Benchmark preparation

`bentoo` operates on *benchmark suites*. A benchmark suite is a collection of *benchmarks* organized in a single directory.
A benchmark is a project that your tool can analyze that has a `truth.sarif` file in its root that describes the vulnerabilities present in the project.
For info on how to prepare `truth.sarif` files for your benchmark, please consult the [bentoo-sarif format](../bentoo-sarif/format.md) section.

If you have run the reference run script, you can observe a simple benchmark suite
consisting of two versions of a single project in the `playground/play/benchmark` directory.
Each version is a separate benchmark and has its own `truth.sarif` file.

```sh
playground/play/benchmark/
  plexus-utils-3.0.14/
    truth.sarif
    ...
  plexus-utils-3.0.16/
    truth.sarif
```

In both `truth.sarif` files you can see one vulnerability descirbed. It has a list of locations related to it and its CWE classification (CWE-78).
`plexus-utils-3.0.14` has the `kind` field set to `fail`, indicating that it is a true positive (the vulnerability is actually present in code).
`plexus-utils-3.0.16`, on the other hand, has this field set to `pass`, indicated that the vulnerability has been fixed and it is now a false positive.

## 2. Runner script preparation

In order for `bentoo` to run your tools on a given benchmark suite, a *runner script* must be prepared. This script must accept one positional argument, the benchmark root directory, and then run your tool and output analysis results to standard output. For detailed info on how the runner script should behave, please consult the [runner script](../tool/runner_script.md) section. Example runners scripts are available in the `/tool_runners` directory.

If you follow along with the example, the runner scripts used for running `Insider` and `CodeQL` on the example benchmark also reside in the `/tool_runners` directory.

Usually, a runner script is a simple shell script that looks somewhat like this:
```bash
#!/usr/bin/env bash

# This will be the path to a benchmark root
benchmark_root=$1

# Supply options required for your tool and feed it the benchmark root
# You may also redirect any logs produced by your tool to standard error,
# it will be avaiable for inspection after the run
# Important: The standard output MUST contain the analysis report ONLY, do not output any logs there
mySASTtool analyze --opt1 value1 --opt2 value2 $benchmark_root -o output_file 1>&2

# Forward analysis results to standard output
cat output_file
```

You can do additional things in your script before running the tool (compiling the project, setting up a docker container, etc.)
If your tool itself satisfies the requirements for runner scripts, you can just use it itself in tools configuration.

If your tool does not produce its analysis results in the bentoo-sarif format, you will also have to provide a parse command
to convert your tool's output to bentoo-sarif. This command is again an executable or a script that accepts the path to a file with
your tool's output as its only positional argument, converts it to bentoo-sarif and outputs it to standard output.

## 3. Tools and Runs descriptions

`bentoo` uses two TOML-based files to describe how to run tools on benchmarks, called *tools descriptions* and *runs descriptions*.
The runs description describes what tools to run on what benchmarks and is unique for every benchmark suite.
A simple runs description can be generated automatically with the `bentoo template` command and then placed to the root directory of the benchmark suite.
The tools desctiption describes runner scripts and their configs and is usually shared between different benchmark suites.
For more info on how to generate those files, please consult [tools](../tool/tools_desctiption.md) and [runs](../benchmark/runs_desctiption.md) descriptions sections.

Assuming that the runner scripts for our reference tools are shell scripts `insider.sh` and `codeql.sh` respectively,
our tools description might look something like this (let the file be called `tools.toml`):

```TOML
# Runner scripts are listed in the 'tools' array
[[tools]]
# Names of scripts and configs are required for further identification
# Pairs (script_name, config_name) must be unique
name = "Insider"
# Paths to actual scripts are relative to the location of the tools configuration file
script = "insider.sh"
# This command is used for parsing your tool's output to bentoo-sarif
# If your tool produces bentoo-sarif directly, this field is not needed
# bentoo has built-in converters for insider and CodeQL, so let us utilize these
parse_command = { command = "bentoo", args = "convert insider" }

# Every script might have one or more configs
# It might be useful if you want to run your tool several times with different heuristics
# Or if your tool needs to be explicitly told the language, build system, etc. of the project
# At least one config must be specified, even if it is trivial like below
[[tools.configs]]
name = "Default"
args = ""

# Second tool
[[tools]]
name = "CodeQL"
script = "codeql.sh"
parse_command = { command = "bentoo", args = "convert codeql" }

[[tools.configs]]
name = "Default"
args = ""
```

And then we can generate a basic runs description for our benchmark with the following command:
```
bentoo template --tools tools.toml playground/play/benchmark > runs.toml
```

This will generate the following runs description:

```TOML
[[runs]]
# Root paths are relative to the location of the runs description file,
# so runs.toml should be placed in the playground/play/benchmark directory
roots = [
    "plexus-utils-3.0.14",
    "plexus-utils-3.0.16",
]

# All the tools listed in the tools subarray will be run on every root in this runs array element
[[runs.tools]]
script = "Insider"
config = "Default"

[[runs.tools]]
script = "CodeQL"
config = "Default"
```

The generated description will tell `bentoo` to run both tools on both benchmarks.

## 4. Actual run

After you have your benchmark suite, runner scripts, tools and runs descriptions ready, there is a one-shot command to run your tools on your benchmarks and then
parse, evaluate and summarize their results. The basic use of the command looks like this:

```
bentoo bench --tools path/to/tools/description.toml --runs --tools path/to/runs/description.toml output_directory
```

So, in our example `bentoo bench` is invoked as:

```
bentoo bench --tools tool_runners/tools.toml --runs playground/play/benchmark/runs.toml playground/play/output
```

`bentoo`'s output should be this:

```
Evaluating tools on benchmarks. Total run count: 4
1/4: Processing configuration Insider/Default on plexus-utils-3.0.14
Runner: No metadata found for the run, running
2/4: Processing configuration CodeQL/Default on plexus-utils-3.0.14
Runner: No metadata found for the run, running
Parser: CodeQL/Default on plexus-utils-3.0.14 has not run succesfully, skipping
Evaluator: No parsed results available for CodeQL/Default on plexus-utils-3.0.14, skipping
3/4: Processing configuration Insider/Default on plexus-utils-3.0.16
Runner: No metadata found for the run, running
4/4: Processing configuration CodeQL/Default on plexus-utils-3.0.16
Runner: No metadata found for the run, running
Evaluation done
Summarizer: CodeQL/Default on plexus-utils-3.0.14 hasn't been evaluated, skipping
Summarization done
```

So, `bentoo` has run two tools on 2 benchmarks each (for a total of 4 runs)
and evaluated and summarized the results.
The second run (`CodeQL/Default` on `plexus-utils-3.0.14`) did not finish successfully,
so the results could not be parsed and evaluated (`Parser` and `Evaluator` messages indicate that).

This will put the bench results in the `output_directory` for further inspection.
The output directory structure mirrors that of the benchmark suite directory.

The directory will have the standard output and standard error of each run along
with run metadata and parse and evaluation results.

In our example, the output directory looks like this:
```
output/
  summary.json
  plexus-utils-3.0.14/
    CodeQL_Default.err
    CodeQL_Default.out
    CodeQL_Default.metadata
    Insider_Default.json
    Insider_Default.sarif
    Insider_Default.err
    Insider_Default.out
    Insider_Default.metadata
  plexus-utils-3.0.16/
    CodeQL_Default.json
    CodeQL_Default.sarif
    CodeQL_Default.err
    CodeQL_Default.out
    CodeQL_Default.metadata
    Insider_Default.json
    Insider_Default.sarif
    Insider_Default.err
    Insider_Default.out
    Insider_Default.metadata
```

## 5. Evaluation results

For each pair (tool, benchmark) in the runs configuration,
there will be a `.json` file containing the evaluation results
of this run against the benchmark's ground truth (`truth.sarif` file).

The evaluation looks at every vulnerability described in the ground truth
and evaluates whether on not the tool was able to find that vulnerability.
It also records if this vulnerability is a true positive or a false positive.

The evaluation happens across multiple location precision levels.
One precision level considers only file-precise location reporting,
so if the tool was able to find the vulnerability in the file but reported
a wrong location within that file, it is still considered to have found the vulnerability.
The other precision level requires tools to report locations within files more accurately.

The evaluation also happens across multiple CWE-precision levels.
By default, the tool is considered to have found the vulnerability only if
its reported CWE is more precise that the CWE described in the ground truth.
Another precision level takes more broad CWE classes
(for now, [CWE-1000](https://cwe.mitre.org/data/definitions/1000.html))
and requires the tool only to report a CWE in the same class as the CWE in the ground truth.

## 6. Summarization results

Also, for the whole benchmark suite, there will be a single `summary.json` file
that describes general information about each tool across all benchmarks in the benchmark suite.
The summary will have such [common metrics](https://en.wikipedia.org/wiki/Confusion_matrix) 
as true positive rate, false positive rate, precision, recall, f1 score and more for each
participating tool.

For example, the `summary.json` file for our example run looks like this:
```json5
{
  // TBD
}
```
