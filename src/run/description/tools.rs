use std::{fmt::Display, fs, path::PathBuf};

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ParseCommand {
    pub command: String,
    pub args: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Script {
    pub script: String,
    pub name: String,
    pub configs: Vec<Config>,
    pub parse_command: Option<ParseCommand>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Config {
    pub name: String,
    pub args: String,
}

#[derive(Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Tools {
    pub tools: Vec<Script>,
}

#[derive(Clone, PartialOrd, Ord, Hash, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Tool {
    pub script: String,
    pub config: String,
}

impl Display for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.script, self.config)
    }
}

impl Tools {
    pub fn get(&self, id: &Tool) -> (&Script, &Config) {
        let tool = self.tools.iter().find(|x| (x.name == id.script)).unwrap();

        let config = tool.configs.iter().find(|x| (x.name == id.config)).unwrap();

        (tool, config)
    }
}

pub struct ToolsInfo {
    pub root: PathBuf,
    pub tools: Tools,
}

impl ToolsInfo {
    pub fn new(file: PathBuf) -> Self {
        let tools: Tools = toml::from_str(
            fs::read_to_string(&file)
                .expect("error: could not read tools description")
                .as_str(),
        )
        .expect("error: failed to parse tools description");
        ToolsInfo {
            root: file.canonicalize().unwrap().parent().unwrap().to_path_buf(),
            tools,
        }
    }
}
