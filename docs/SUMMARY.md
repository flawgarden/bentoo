# bentoo user documentation

1. General
  - [Getting started](general/getting_started.md) -
    This section is a step-by-step guide to running your tool on your benchmark suite with bentoo.
  - [Glossary](general/glossary.md) -
    This section is a glossary of terms used throughout the documentation.

2. Bentoo-sarif
  - [Format](bentoo-sarif/format.md) -
    bentoo uses a SARIF-based to describe both ground truth and analysis results from tools.
    This section describes the format and how it is used.

3. Tool support
  - [Runner script](tool/runner_script.md) -
    bentoo expects a benchmarked tool to be invokable with a single command on a benchmark root.
    This section describes the expected behavior of the runner and how bentoo and the runner interoperate.
  - [Tools description](tool/tools_description.md) - in order to know how to use your runners, bentoo uses a
    TOML-based description of your tool's configuations. This section describes the description format and
    where it is used.

4. Benchmark
  - [Benchmark structure](benchmark/structure.md) -
    this section describes the general structure of a benchmark suite compatible with bentoo.
  - [Runs description](benchmark/runs_description.md) - in order to know which tool configurations to run on
    which benchmarks, bentoo uses a TOML-based description of run configurations. This section describes the
    description format and where it is used and shows how to generate run description templates for your
    benchmark suites automatically.


