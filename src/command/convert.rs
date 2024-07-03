use std::path::PathBuf;

use serde_sarif::sarif::Sarif;

use crate::convert::tool::{bearer, codeql, contrast_scan, insider, semgrep, snyk, sonarqube};

pub fn convert_from(format: String, file: PathBuf) -> Sarif {
    match format.as_str() {
        "insider" => insider::from_file(file.as_path()),
        "codeql" => codeql::from_file(file.as_path()),
        "snyk" => snyk::from_file(file.as_path()),
        "semgrep" => semgrep::from_file(file.as_path()),
        "sonarqube" => sonarqube::from_file(file.as_path()),
        "bearer" => bearer::from_file(file.as_path()),
        "contrast_scan" => contrast_scan::from_file(file.as_path()),
        _ => {
            panic!("Error: unknown tool");
        }
    }
}
