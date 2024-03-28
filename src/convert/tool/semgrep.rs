use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use serde_sarif::sarif::{ReportingDescriptor, Sarif};

use crate::convert::common::{RuleMap, ToolName, ToolSarif};

struct SemgrepReport {
    pub sarif: Sarif,
}

impl From<SemgrepReport> for Sarif {
    fn from(report: SemgrepReport) -> Self {
        report.sarif
    }
}

impl RuleMap for SemgrepReport {
    fn collect_rules_map(
        notifications: Option<&Vec<ReportingDescriptor>>,
    ) -> HashMap<String, HashSet<u64>> {
        const CWE_TAG_PREFIX: &str = "CWE-";
        let mut rule_to_cwes: HashMap<String, HashSet<u64>> = HashMap::new();
        if let Some(reporting_descriptors) = notifications {
            for reporting_descriptor in reporting_descriptors {
                reporting_descriptor
                    .properties
                    .as_ref()
                    .map(|property_bag| {
                        property_bag.tags.as_ref().map(|tags_vect| {
                            let cwes = tags_vect
                                .iter()
                                .filter_map(|tag| tag.strip_prefix(CWE_TAG_PREFIX))
                                .map(|tag| {
                                    let tag = tag.split(':').take(1).next().unwrap();
                                    let cwe: u64 = tag.parse().unwrap();
                                    cwe
                                })
                                .collect();
                            rule_to_cwes.insert(reporting_descriptor.id.to_string(), cwes);
                        })
                    });
            }
        };
        rule_to_cwes
    }
}

impl ToolName for SemgrepReport {
    const TOOL_NAME: &'static str = "semgrep";
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let report: Sarif = serde_json::from_str(string).unwrap();
    SemgrepReport { sarif: report }.build_tool_sarif()
}
