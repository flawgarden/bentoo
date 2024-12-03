use std::{fs, path::Path};

use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    RegionBuilder, ResultBuilder, RunBuilder, Sarif, SarifBuilder, ToolBuilder,
    ToolComponentBuilder,
};

struct CPPCheckVulnerability {
    file: String,
    line: i64,
    column: i64,
    cwe: String,
}

impl CPPCheckVulnerability {
    fn from_string(string: &str) -> Self {
        let split = string.split(' ').collect::<Vec<&str>>();
        assert!(split.len() == 4);
        let file = split[0].to_string();
        let line: i64 = split[1].parse().unwrap();
        let column: i64 = split[2].parse().unwrap();
        let cwe: String = "CWE-".to_string() + split[3];
        CPPCheckVulnerability {
            file,
            line,
            column,
            cwe,
        }
    }
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let vul_strings = string.lines();

    let mut vuls: Vec<CPPCheckVulnerability> = vec![];
    for vul_string in vul_strings {
        vuls.push(CPPCheckVulnerability::from_string(vul_string));
    }

    let mut results = vec![];
    let mut result_builder = ResultBuilder::default();
    for report in vuls {
        if report.cwe == "0" {
            continue;
        }
        result_builder.rule_id(report.cwe);
        let region = RegionBuilder::default()
            .start_line(report.line)
            .end_line(report.line)
            .start_column(report.column)
            .end_column(report.column)
            .build()
            .unwrap();
        let artifact = ArtifactLocationBuilder::default()
            .uri(report.file)
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
        let sarif_message = MessageBuilder::default().text("").build().unwrap();
        result_builder.message(sarif_message);
        results.push(result_builder.build().unwrap());
    }

    let tool = ToolBuilder::default()
        .driver(
            ToolComponentBuilder::default()
                .name("CPPCheck")
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
