use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use serde::Deserialize;
use serde_json::Value;
use serde_sarif::sarif::{ReportingDescriptor, Sarif};

use crate::convert::common::{RuleMap, ToolName, ToolSarif};

struct GosecReport {
    pub sarif: Sarif,
}

impl From<GosecReport> for Sarif {
    fn from(report: GosecReport) -> Self {
        report.sarif
    }
}

#[derive(Debug, Deserialize)]
struct GosecRuleInfo {
    pub cwe: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct GosecRuleMap {
    pub rule_mapping: HashMap<String, GosecRuleInfo>,
}

impl GosecRuleMap {
    pub fn from_json(json: Value) -> Self {
        serde_json::from_value(json).expect("Rule mapping parsing failed")
    }

    pub fn from_string(string: &str) -> Self {
        let json: Value = serde_json::from_str(string).unwrap();
        Self::from_json(json)
    }

    pub fn new() -> Self {
        let rule_mapping: &str = include_str!("../../../taxonomies/gosec_rule_mapping.json");
        Self::from_string(rule_mapping)
    }
}

impl RuleMap for GosecReport {
    fn collect_rules_map(
        _notifications: Option<&Vec<ReportingDescriptor>>,
    ) -> HashMap<String, HashSet<u64>> {
        let rules = GosecRuleMap::new();
        let mut rule_to_cwes: HashMap<String, HashSet<u64>> = HashMap::new();
        for (rule, cwes) in rules.rule_mapping {
            let cwes: HashSet<_> = cwes.cwe.iter().copied().collect();
            rule_to_cwes.insert(rule, cwes);
        }
        rule_to_cwes
    }
}

impl ToolName for GosecReport {
    const TOOL_NAME: &'static str = "gosec";
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let report: Sarif = serde_json::from_str(string).unwrap();
    GosecReport { sarif: report }.build_tool_sarif()
}
