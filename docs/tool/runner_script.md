# Runner script

`bentoo` expects SAST tools to be executable with a single command that accepts a single positional argument, the benchmark root. It may also accept keyword arguments, they should be specified in the config section of the [tools description file](tools_description.md). The script must output the analysis results in standard output, it may also use standard error for logging. Runner script examples are in `/tool_runners` directory.

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

The runner scripts acts as an interface bridge between `bentoo` and your SAST tool.
It will be run on a temporary copy of each benchmark your tool will be run on.
If your tool fails when it is used by `bentoo`, its standard error output and exit code will be available for inspection
in the benchmark output directory, this information can be used for debugging.
