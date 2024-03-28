# Glossary

* **bentoo-sarif** - A SARIF-based format bentoo uses to represent both ground truth and tools' analysis results.
                     Your tool should be able to produce results in this format directly or provide a converter to it

* **truth.sarif file** - A file in bentoo-sarif that describes vulnerabilities (true and false positive) in the given project

* **benchmark** - A project for a SAST tool analyze along with the corresponding truth.sarif file. The truth.sarif file must
                  reside in the root of the project

* **benchmark suite** - A collection of benchmarks organized in a directory tree with the leaves corresponding to benchmarks

* **runner script** - A command used to run your SAST tool on benchmarks.

* **script config** - A set of arguments to pass to your runner script in addition to the benchmark itself.

* **tool** - A runner script along with one of its configs.

* **tools description** - A TOML-based file that describes your runner scripts and their configs.

* **runs description** - A TOML-based file that describes what tools to run on what benchmarks in the given benchmark suite.
