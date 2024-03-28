# runs description file

`bentoo` uses a TOML-based file to get information on what tools to run on what benchmarks in the given benchmark suite.

Given the following benchmark suite structure:
```
/benchmark_suite
  /benchmark_group_1
    /benchmark_1
      /truth.sarif
      ...
    /benchmark_2
      /truth.sarif
      ...
  /benchmark_group_2
    /benchmark_3
      /truth.sarif
      ...
  /benchmark_4
    /truth.sarif
   ...
```

A possible runs description for this benchmark suite is as follows:
```TOML
# Every element of the runs array specifies an array of benchmark roots and an array of tools
# bentoo will run every possible (root, tool) pair in the resulting matrix
[[runs]]
# Paths to benchmark roots are relative to the location of the runs description file
# In this example, the runs description file should be placed in the benchmark suite root
roots = [
    "benchmark_group_1/benchmark_1",
    "benchmark_group_1/benchmark_2",
    "benchmark_group_2/benchmark_3",
    "benchmark_4",
]

# One tool is a (script, config) pair, every tool will be run on every benchmark root
# The (script, config) info will be taken from the supplied tools description file
[[runs.tools]]
script = "ScriptA"
config = "ConfigA"

[[runs.tools]]
script = "ScriptA"
config = "ConfigB"

[[runs.tools]]
script = "ScriptB"
config = "ConfigA"

[[runs.tools]]
script = "ScriptB"
config = "ConfigB"

[[runs]]
# You may add more than one element in the runs array
```

The `bentoo template` command accepts a path to a benchmark script and a tools description file and generates a runs desctiption which will run every tool on every benchmark in the given suite. The generated file will have paths to benchmark roots relative to the root of the benchmark suite and therefore must be placed in the benchmark suite root directory.
