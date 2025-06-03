use serde::Deserialize;
use std::{fs, path::Path};

use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    ResultBuilder, RunBuilder, Sarif, SarifBuilder, ToolBuilder, ToolComponentBuilder,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CoverityResult {
    #[serde(rename = "Type")]
    pub message: String,
    pub c_w_e: String,
    pub file: String,
}

fn from_report(report: &Vec<CoverityResult>) -> Sarif {
    let mut results = vec![];
    let mut result_builder = ResultBuilder::default();
    for vul in report {
        result_builder.rule_id(format!("CWE-{}", vul.c_w_e));
        let file = vul.file.strip_prefix("/").unwrap();
        let artifact = ArtifactLocationBuilder::default()
            .uri(file)
            .build()
            .unwrap();
        let location = PhysicalLocationBuilder::default()
            .artifact_location(artifact)
            .build()
            .unwrap();
        let location = LocationBuilder::default()
            .physical_location(location)
            .build()
            .unwrap();
        result_builder.locations(vec![location]);
        let sarif_message = MessageBuilder::default()
            .text(vul.message.clone())
            .build()
            .unwrap();
        result_builder.message(sarif_message);
        results.push(result_builder.build().unwrap());
    }

    let tool = ToolBuilder::default()
        .driver(
            ToolComponentBuilder::default()
                .name("coverity")
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
    let csv: Result<Vec<CoverityResult>, _> = csv::Reader::from_reader(string.as_bytes())
        .deserialize()
        .collect();
    let csv = csv.unwrap();
    from_report(&csv)
}
