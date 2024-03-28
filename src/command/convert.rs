use std::path::PathBuf;

use serde_sarif::sarif::Sarif;

use crate::convert::tool::{codeql, insider, semgrep, snyk, sonarqube};

pub fn convert_from(format: String, file: PathBuf) -> Sarif {
    match format.as_str() {
        "insider" => insider::from_file(file.as_path()),
        "codeql" => codeql::from_file(file.as_path()),
        "snyk" => snyk::from_file(file.as_path()),
        "semgrep" => semgrep::from_file(file.as_path()),
        "sonarqube" => sonarqube::from_file(file.as_path()),
        _ => {
            panic!("Error: unknown tool");
        }
    }
}
