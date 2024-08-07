use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use serde_sarif::sarif::{ReportingDescriptor, Sarif};

use crate::convert::common::{collect_tags_rules_map, RuleMap, ToolName, ToolSarif};

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
        collect_tags_rules_map(notifications, CWE_TAG_PREFIX)
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
