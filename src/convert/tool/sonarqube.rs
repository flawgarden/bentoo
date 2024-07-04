use std::{collections::HashMap, fs, path::Path};

use serde::Deserialize;
use serde_json::Value;
use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    RegionBuilder, ResultBuilder, RunBuilder, Sarif, SarifBuilder, ToolBuilder,
    ToolComponentBuilder,
};

use crate::reference::truth::{CWEs, CWE};

#[derive(Debug, Deserialize)]
struct RuleInfo {
    pub cwe: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct RuleMap {
    pub rule_mapping: HashMap<String, RuleInfo>,
}

impl RuleMap {
    pub fn from_json(json: Value) -> Self {
        serde_json::from_value(json).expect("Rule mapping parsing failed")
    }

    pub fn from_string(string: &str) -> Self {
        let json: Value = serde_json::from_str(string).unwrap();
        Self::from_json(json)
    }

    pub fn new() -> Self {
        let rule_mapping: &str = include_str!("../../../taxonomies/sonarqube_rule_mapping.json");
        Self::from_string(rule_mapping)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TextRange {
    pub start_line: i64,
    pub end_line: i64,
    pub start_offset: i64,
    pub end_offset: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Issue {
    pub rule: String,
    pub component: String,
    pub message: String,
    pub text_range: TextRange,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Hotspots {
    pub rule_key: String,
    pub component: String,
    pub message: String,
    pub text_range: TextRange,
}

impl From<Hotspots> for Issue {
    fn from(hotspots: Hotspots) -> Self {
        Self {
            rule: hotspots.rule_key,
            component: hotspots.component,
            message: hotspots.message,
            text_range: hotspots.text_range,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SonarQubeReport {
    pub issues: Vec<Issue>,
    pub hotspots: Vec<Hotspots>,
}

fn from_json(json: Value) -> Sarif {
    let rules = RuleMap::new();
    let sonarqube_report: SonarQubeReport = serde_json::from_value(json).unwrap();
    let mut results = vec![];
    let report: Vec<Issue> = sonarqube_report
        .issues
        .into_iter()
        .chain(sonarqube_report.hotspots.into_iter().map(From::from))
        .collect();
    for issue in &report {
        let rule = issue.rule.split_once(':').unwrap().1;
        if !rules.rule_mapping.contains_key(rule) {
            continue;
        }
        let cwes = rules.rule_mapping[rule]
            .cwe
            .iter()
            .map(|cwe| CWE(*cwe))
            .collect();
        let cwes = CWEs(cwes);
        let mut result_builder = ResultBuilder::default();
        let text_range = &issue.text_range;
        let region = RegionBuilder::default()
            .start_line(text_range.start_line)
            .end_line(text_range.end_line)
            .start_column(text_range.start_offset)
            .end_column(text_range.end_offset)
            .build()
            .unwrap();
        let path = issue.component.split_once(':').unwrap().1;
        let artifact = ArtifactLocationBuilder::default()
            .uri(path)
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
            .text(&issue.message)
            .build()
            .unwrap();
        result_builder.message(sarif_message);

        let cwe = format!("{}", cwes);
        result_builder.rule_id(cwe);
        results.push(result_builder.build().unwrap());
    }
    let tool = ToolBuilder::default()
        .driver(
            ToolComponentBuilder::default()
                .name("sonarqube")
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
