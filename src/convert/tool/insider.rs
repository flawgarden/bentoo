use serde::Deserialize;
use serde_json::Value;
use std::{fs, path::Path};

use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    RegionBuilder, ResultBuilder, RunBuilder, Sarif, SarifBuilder, ToolBuilder,
    ToolComponentBuilder,
};

#[derive(Debug, Deserialize)]
struct InsiderReport {
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vulnerability {
    pub cwe: String,
    pub line: i64,
    pub column: i64,
    pub class_message: String,
    pub description: String,
}

fn from_json(json: Value) -> Sarif {
    let mut results = vec![];
    let insider_report: InsiderReport = serde_json::from_value(json).unwrap();
    let mut result_builder = ResultBuilder::default();
    for vul in insider_report.vulnerabilities {
        result_builder.rule_id(vul.cwe);
        let line = vul.line;
        let column = vul.column;
        let region = RegionBuilder::default()
            .start_line(line)
            .end_line(line)
            .start_column(column)
            .end_column(column)
            .build()
            .unwrap();
        let message = vul.class_message.as_str().split(' ').next().unwrap();
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
        let sarif_message = MessageBuilder::default()
            .text(vul.description)
            .build()
            .unwrap();
        result_builder.message(sarif_message);
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
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let json: Value = serde_json::from_str(string).unwrap();
    from_json(json)
}
