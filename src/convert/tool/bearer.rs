use std::{fs, path::Path};

use serde::Deserialize;
use serde_json::Value;
use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    RegionBuilder, ResultBuilder, RunBuilder, Sarif, SarifBuilder, ToolBuilder,
    ToolComponentBuilder,
};

#[derive(Debug, Deserialize)]
struct Column {
    start: i64,
    end: i64,
}

#[derive(Debug, Deserialize)]
struct Sink {
    start: i64,
    end: i64,
    column: Column,
}

#[derive(Debug, Deserialize)]
struct Finding {
    pub cwe_ids: Vec<String>,
    pub sink: Sink,
    pub title: String,
    pub filename: String,
}

#[derive(Debug, Deserialize)]
struct BearerReport {
    pub findings: Option<Vec<Finding>>,
}

fn from_json(json: Value) -> Sarif {
    let report: BearerReport = serde_json::from_value(json).unwrap();
    let mut results = vec![];

    for finding in report.findings.unwrap_or_default() {
        let mut result_builder = ResultBuilder::default();
        let prefixed: Vec<String> = finding
            .cwe_ids
            .iter()
            .map(|id| format!("CWE-{}", id))
            .collect();
        result_builder.rule_id(prefixed.join(","));

        let region = RegionBuilder::default()
            .start_line(finding.sink.start)
            .end_line(finding.sink.end)
            .start_column(finding.sink.column.start)
            .end_column(finding.sink.column.end)
            .build()
            .unwrap();
        let artifact = ArtifactLocationBuilder::default()
            .uri(finding.filename)
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

        let message = MessageBuilder::default()
            .text(finding.title)
            .build()
            .unwrap();

        result_builder.message(message);
        results.push(result_builder.build().unwrap());
    }

    let tool = ToolBuilder::default()
        .driver(
            ToolComponentBuilder::default()
                .name("bearer")
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
