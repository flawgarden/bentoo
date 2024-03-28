# benchmark and benchmark suite structure

A benchmark is a single project that your SAST tool analyzes.
The presence of a `truth.sarif` file indicates that the directory is a benchmark root directory.

A benchmark suite is a collection of benchmark organized in a single directory.
The benchmarks inside a suite form a tree structure, it does not have to be flat.
The example structure might look something like this:
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
The output directory for benchmark results will mirror this tree structure:
```
/output
  /benchmark_group_1
    /benchmark_1
      (tool results for benchmark_1)
    /benchmark_2
      (tool results for benchmark_2)
  /benchmark_group_2
    /benchmark_3
      (tool results for benchmark_3)
  /benchmark_4
    (tool results for benchmark_4)
```

The benchmark suite must be supplied with a runs description file. It is usually put in the benchmark suite root directory.
For more information, please consult the [runs description section](runs_description.md).
