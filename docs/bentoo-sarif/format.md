# bentoo-sarif format

bentoo-sarif is a subset of [SARIF](https://sarifweb.azurewebsites.net/) that is used to represent vulnerabilities in benchmarks and tool analysis results.
It is then used to compare tool results against ground truth.

The format is as follows:
```json5
{
  // The following two fields are fixed and a part of the SARIF format specification
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  // This field contains separate analyses, for our purposes there will usually be only one array element
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "<benchmark name or tool name>"
        }
      },
      // Vector of vulnerabilities
      "results": [
        {
          // This field is present only in ground truth (truth.sarif) files
          // "fail" means it is a true positive, "pass" - a false positive
          "kind": "<fail/pass>",
          // This field indicates the type of found vulnerability
          // bentoo expects ground truths and tool results to use the CWE classification
          "ruleId": "CWE-<CWE_id>",
          // Locations related to the vulnerability
          "locations": [
            {
              "physicalLocation": {
                // According to SARIF spec
              },
              "logicalLocations": [
                // According to SARIF spec
              ]
            },
            // More locations can follow
          ]
        }
      ]
    }
  ]
}
```
