use std::{fs, path::Path};

use serde_json::Value;
use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    RegionBuilder, ResultBuilder, RunBuilder, Sarif, SarifBuilder, ToolBuilder,
    ToolComponentBuilder,
};

fn from_json(json: &Value) -> Sarif {
    let mut results = vec![];

    if let Value::Array(vulns) = &json["vulnerabilities"] {
        let mut result_builder = ResultBuilder::default();
        for vul in vulns {
            if let Value::String(cwe) = &vul["cwe"] {
                result_builder.rule_id(cwe);
            }
            if let Value::Number(line) = &vul["line"] {
                if let Value::Number(column) = &vul["column"] {
                    if let Value::String(message) = &vul["classMessage"] {
                        let line = line.as_i64().unwrap();
                        let column = column.as_i64().unwrap();
                        let region = RegionBuilder::default()
                            .start_line(line)
                            .end_line(line)
                            .start_column(column)
                            .end_column(column)
                            .build()
                            .unwrap();
                        let message = message.as_str().split(' ').next().unwrap();
                        let artifact = ArtifactLocationBuilder::default()
                            .uri(message)
                            .build()
                            .unwrap();
                        let location = PhysicalLocationBuilder::default()
                            .artifact_location(artifact)
                            .region(region)
                            .build()
                            .unwrap();
                        let location = LocationBuilder::default()
                            .physical_location(location)
                            .build()
                            .unwrap();
                        result_builder.locations(vec![location]);
                    }
                }
            }
            if let Value::String(description) = &vul["description"] {
                let sarif_message = MessageBuilder::default().text(description).build().unwrap();
                result_builder.message(sarif_message);
            }
            results.push(result_builder.build().unwrap());
        }
        let tool = ToolBuilder::default()
            .driver(
                ToolComponentBuilder::default()
                    .name("insider")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let run = RunBuilder::default()
            .tool(tool)
            .results(results)
            .build()
            .unwrap();

        SarifBuilder::default()
            .version("2.1.0")
            .runs(vec![run])
            .build()
            .unwrap()
    } else {
        panic!("Parsing failed.");
    }
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let json: Value = serde_json::from_str(string).unwrap();
    from_json(&json)
}
