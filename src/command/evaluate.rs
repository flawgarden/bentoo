use std::path::PathBuf;

use itertools::Itertools;

use crate::{
    reference::{
        taxonomy::{Taxonomy, TaxonomyVersion},
        truth::{self, ToolResults},
    },
    run::{description::runs::RunsInfo, directory::Directory, metadata::ParseStatus},
};

use super::compare;

pub struct Evaluator<'a> {
    runs: &'a RunsInfo,
    output: PathBuf,
    taxonomy: Taxonomy,
}

impl<'a> Evaluator<'a> {
    pub fn new(runs: &'a RunsInfo, output: PathBuf) -> Self {
        Evaluator {
            runs,
            output,
            taxonomy: Taxonomy::from_known_version(&TaxonomyVersion::default()),
        }
    }

    pub fn evaluate_one(&self, directory: &Directory, detailed: bool) {
        let output_path = self.output.join(directory.benchmark);
        let metadata = directory.metadata_read();
        if metadata.is_none() {
            println!(
                "Evaluator: No metadata for {} on {}, skipping",
                directory.tool,
                directory.benchmark.display()
            );
            return;
        }
        let mut metadata = metadata.unwrap();
        if metadata.parsed != ParseStatus::Yes {
            println!(
                "Evaluator: No parsed results available for {} on {}, skipping",
                directory.tool,
                directory.benchmark.display()
            );
            return;
        }
        if !output_path.join("truth.sarif").exists() {
            println!(
                "Evaluator: No truth.sarif found in {}, skipping",
                directory.benchmark.display()
            );
        }
        let tool_results = ToolResults::try_from(directory.sarif_path().as_path())
            .expect("Error: could not load tool results;");
        let truth = truth::TruthResults::try_from(output_path.join("truth.sarif").as_path())
            .expect("Error: could not load truth.sarif");
        let card = compare::evaluate_tool(&truth, &tool_results, Some(&self.taxonomy), detailed);
        serde_json::to_writer_pretty(directory.evaluate_file_write(), &card)
            .expect("error: failure to write json result card");
        metadata.evaluated = true;
        directory.metadata_write(&metadata);
    }

    pub fn evaluate_all(&self, detailed: bool) {
        let roots_tools = self
            .runs
            .runs
            .runs
            .iter()
            .flat_map(|run| run.roots.iter().cartesian_product(run.tools.iter()));

        println!("Evaluating parsed results in {}", self.output.display());

        for (root, tool) in roots_tools {
            let directory = Directory::new(&self.output, root, tool);
            self.evaluate_one(&directory, detailed);
        }

        println!("Evaluation done");
    }
}
