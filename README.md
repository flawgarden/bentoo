# bentoo

`bentoo` is a simple command-line utility to run SAST tools on benchmark suites and evaluate analysis results.

It uses a [SARIF](https://sarifweb.azurewebsites.net/)-based format called [bentoo-sarif](docs/bentoo-sarif/format.md)
to represent both ground truth about vulnerabilities found in benchmarks and SAST tools' analysis results.

Vulnerabilities are described in terms of the [CWE](https://cwe.mitre.org/) vulnerability classification.

`bentoo` can run your SAST tools on your benchmarks via *runner scripts* and compare the results against ground truth
described in special `truth.sarif` files in each benchmark.

To start using the tool, please take a look at the [getting started](docs/general/getting_started.md) guide.
