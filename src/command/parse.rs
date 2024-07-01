use std::{io::Read, path::PathBuf, process::Command};

use itertools::Itertools;
use serde_sarif::sarif::Sarif;

use crate::{
    reference::truth::{self},
    run::{
        description::{runs::RunsInfo, tools::ToolsInfo},
        directory::Directory,
        metadata::{self, ParseStatus},
    },
};

pub struct Parser<'a> {
    runs: &'a RunsInfo,
    tools: &'a ToolsInfo,
    output: PathBuf,
}

impl<'a> Parser<'a> {
    pub fn new(runs: &'a RunsInfo, tools: &'a ToolsInfo, output: PathBuf) -> Self {
        Parser {
            runs,
            tools,
            output,
        }
    }

    pub fn parse_one(&self, directory: &Directory) {
        let metadata = directory.metadata_read();
        if metadata.is_none() {
            println!(
                "Parser: No metadata for {} on {}, skipping",
                directory.tool,
                directory.benchmark.display()
            );
            return;
        }
        let mut metadata = metadata.unwrap();
        if metadata.status != metadata::Status::Exited || metadata.exit_code != 0 {
            println!(
                "Parser: {} on {} has not run succesfully, skipping",
                directory.tool,
                directory.benchmark.display()
            );
            return;
        }
        let (tool, _) = self.tools.tools.get(directory.tool);
        let converted = match &tool.parse_command {
            None => {
                let mut string = String::new();
                directory
                    .out_file_read()
                    .read_to_string(&mut string)
                    .unwrap();
                Some(string)
            }
            Some(command) => Command::new(&command.command)
                .args(command.args.split_whitespace())
                .arg(directory.out_path())
                .output()
                .ok()
                .map(|output| String::from_utf8(output.stdout).unwrap()),
        };

        if let Some(converted) = converted {
            let sarif: Option<Sarif> = serde_json::from_str(converted.as_str()).ok();
            if let Some(sarif) = sarif {
                serde_json::to_writer_pretty(directory.sarif_file_write(), &sarif).unwrap();
                let result = truth::ToolResults::try_from(&sarif);
                if result.is_ok() {
                    metadata.parsed = ParseStatus::Yes;
                    directory.metadata_write(&metadata);
                    return;
                }
            }
        }
        println!(
            "Parser: {} on {} failed to parse",
            directory.tool,
            directory.benchmark.display()
        );
        metadata.parsed = ParseStatus::Failed;
        directory.metadata_write(&metadata);
    }

    pub fn parse_all(&self) {
        let roots_tools = self
            .runs
            .runs
            .runs
            .iter()
            .flat_map(|run| run.roots.iter().cartesian_product(run.tools.iter()));

        println!("Parsing runs output in {}", self.output.display());

        for (root, tool) in roots_tools {
            let directory = Directory::new(&self.output, root, tool);
            self.parse_one(&directory);
        }

        println!("Parsing done");
    }
}
