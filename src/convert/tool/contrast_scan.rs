use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use serde_sarif::sarif::{ReportingDescriptor, Sarif};

use crate::convert::common::{RuleMap, ToolName, ToolSarif};

struct ContrastScanReport {
    pub sarif: Sarif,
}

impl From<ContrastScanReport> for Sarif {
    fn from(report: ContrastScanReport) -> Self {
        report.sarif
    }
}

impl RuleMap for ContrastScanReport {
    fn collect_rules_map(_: Option<&Vec<ReportingDescriptor>>) -> HashMap<String, HashSet<u64>> {
        let mut map: HashMap<String, HashSet<u64>> = HashMap::new();
        map.insert(String::from("reflected-xss"), HashSet::from([79]));
        map.insert(String::from("cmd-injection"), HashSet::from([78]));
        map.insert(String::from("crypto-weak-randomness"), HashSet::from([338]));
        map.insert(String::from("cookie-flags-missing"), HashSet::from([614]));
        map.insert(
            String::from("trust-boundary-violation"),
            HashSet::from([501]),
        );
        map.insert(String::from("sql-injection"), HashSet::from([89]));
        map.insert(String::from("crypto-bad-ciphers"), HashSet::from([327]));
        map.insert(String::from("path-traversal"), HashSet::from([22]));
        map.insert(String::from("xpath-injection"), HashSet::from([643]));
        map.insert(String::from("ldap-injection"), HashSet::from([90]));
        map.insert(String::from("crypto-bad-mac"), HashSet::from([328]));
        map
    }
}

impl ToolName for ContrastScanReport {
    const TOOL_NAME: &'static str = "contrast scan";
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let report: Sarif = serde_json::from_str(string).unwrap();
    ContrastScanReport { sarif: report }.build_tool_sarif()
}
