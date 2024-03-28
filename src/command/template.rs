use std::{
    fs,
    path::{Path, PathBuf},
};

use itertools::Itertools;

use crate::{
    run::description::{
        runs::{Run, Runs},
        tools::{Tool, Tools},
    },
    util,
};

pub(crate) const TRUTH_FILENAME: &str = "truth.sarif";

fn collect_benchmarks(path: &Path) -> Vec<PathBuf> {
    util::find_files_recursive(path, &|file_name| {
        file_name.file_name().unwrap() == TRUTH_FILENAME
    })
    .into_iter()
    .map(|path| path.parent().unwrap().to_path_buf())
    .unique()
    .collect()
}

fn collect_tools(tools_desc: &Tools) -> Vec<Tool> {
    let mut tools = vec![];
    for tool in &tools_desc.tools {
        for config in &tool.configs {
            tools.push(Tool {
                script: tool.name.clone(),
                config: config.name.clone(),
            })
        }
    }
    tools
}

fn generate_runs(path: &Path, tools: &Tools) -> Runs {
    let run = Run {
        roots: collect_benchmarks(path),
        tools: collect_tools(tools),
    };

    Runs { runs: vec![run] }
}

pub fn make_runs_template(root: PathBuf, tools: Option<PathBuf>) -> Runs {
    let tools = tools.map_or(Tools::default(), |tools_path| {
        let tools_str = fs::read_to_string(tools_path)
            .expect("Error: could not read tools description for runs template generation");
        toml::from_str(tools_str.as_str())
            .expect("Error: could not parse tools desctiption for runs template generation")
    });
    generate_runs(root.as_path(), &tools)
}
