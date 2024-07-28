use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use serde_sarif::sarif::{ReportingDescriptor, Sarif};

use crate::convert::common::{RuleMap, ToolName, ToolSarif};

struct SnykReport {
    pub sarif: Sarif,
}

impl From<SnykReport> for Sarif {
    fn from(report: SnykReport) -> Self {
        report.sarif
    }
}

impl RuleMap for SnykReport {
    fn collect_rules_map(
        notifications: Option<&Vec<ReportingDescriptor>>,
    ) -> HashMap<String, HashSet<u64>> {
        fn try_extract_cwes(
            reporting_descriptor: &ReportingDescriptor,
        ) -> Option<(String, HashSet<u64>)> {
            const CWE_TAG_PREFIX: &str = "CWE-";
            let property_bag = reporting_descriptor.properties.as_ref()?;
            let cwes = property_bag.additional_properties.get("cwe")?;
            let cwes = cwes
                .as_array()
                .expect("cwe additional property shold be an array");
            let cwes: HashSet<_> = cwes
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("cwe additional property shold be an array of strings")
                })
                .filter_map(|tag| tag.strip_prefix(CWE_TAG_PREFIX))
                .map(|tag| {
                    let cwe: u64 = tag.parse().unwrap();
                    cwe
                })
                .collect();
            Some((reporting_descriptor.id.to_string(), cwes))
        }

        let mut rule_to_cwes: HashMap<String, HashSet<u64>> = HashMap::new();
        if let Some(reporting_descriptors) = notifications {
            for reporting_descriptor in reporting_descriptors {
                if let Some((rule, cwes)) = try_extract_cwes(reporting_descriptor) {
                    rule_to_cwes.insert(rule, cwes);
                }
            }
        };
        rule_to_cwes
    }
}

impl ToolName for SnykReport {
    const TOOL_NAME: &'static str = "snyk";
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let report: Sarif = serde_json::from_str(string).unwrap();
    SnykReport { sarif: report }.build_tool_sarif()
}
