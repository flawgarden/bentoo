use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[derive(Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Tools {
    pub tools: Vec<Tool>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Tool {
    pub script: String,
    pub name: String,
    pub configs: Vec<ToolConfig>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ToolConfig {
    pub name: String,
    pub args: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Runs {
    pub runs: Vec<Run>,
}

#[derive(Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Run {
    pub roots: Vec<String>,
    pub tools: Vec<ToolID>,
}

#[derive(Clone, Hash, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ToolID {
    pub script: String,
    pub config: String,
}

impl Display for ToolID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}", self.script, self.config)
    }
}
