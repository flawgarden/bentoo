use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use super::tools::Tool;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Runs {
    pub runs: Vec<Run>,
}

#[derive(Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Run {
    pub roots: Vec<PathBuf>,
    pub tools: Vec<Tool>,
}

pub struct RunsInfo {
    pub root: PathBuf,
    pub runs: Runs,
}

impl RunsInfo {
    pub fn new(file: PathBuf) -> Self {
        let runs: Runs = toml::from_str(
            fs::read_to_string(&file)
                .expect("error: could not read runs description")
                .as_str(),
        )
        .expect("error: failed to parse runs description");
        RunsInfo {
            root: file.canonicalize().unwrap().parent().unwrap().to_path_buf(),
            runs,
        }
    }
}
