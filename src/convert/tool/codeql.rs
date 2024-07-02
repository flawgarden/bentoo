use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use serde_sarif::sarif::{ReportingDescriptor, Sarif};

use crate::convert::common::{RuleMap, ToolName, ToolSarif};

struct CodeQLReport {
    pub sarif: Sarif,
}

impl From<CodeQLReport> for Sarif {
    fn from(report: CodeQLReport) -> Self {
        report.sarif
    }
}

impl RuleMap for CodeQLReport {
    fn collect_rules_map(
        notifications: Option<&Vec<ReportingDescriptor>>,
    ) -> HashMap<String, HashSet<u64>> {
        const CWE_TAG_PREFIX: &str = "external/cwe/cwe-";
        let mut rule_to_cwes: HashMap<String, HashSet<u64>> = HashMap::new();
        if let Some(reporting_descriptors) = notifications {
            for reporting_descriptor in reporting_descriptors {
                reporting_descriptor
                    .properties
                    .as_ref()
                    .map(|property_bag| {
                        property_bag.tags.as_ref().map(|tags_vect| {
                            let cwes: HashSet<u64> = tags_vect
                                .iter()
                                .filter_map(|tag| tag.strip_prefix(CWE_TAG_PREFIX))
                                .map(|tag| {
                                    let cwe: u64 = tag.parse().unwrap();
                                    cwe
                                })
                                .collect();
                            if !cwes.is_empty() {
                                rule_to_cwes.insert(reporting_descriptor.id.to_string(), cwes);
                            }
                        })
                    });
            }
        };
        rule_to_cwes
    }
}

impl ToolName for CodeQLReport {
    const TOOL_NAME: &'static str = "codeql";
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let report: Sarif = serde_json::from_str(string).unwrap();
    CodeQLReport { sarif: report }.build_tool_sarif()
}
