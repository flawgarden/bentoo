use std::{path::PathBuf, time::Duration};

use itertools::Itertools;

use crate::{
    command::summarize,
    run::{
        description::{run_count, runs::RunsInfo, tools::ToolsInfo},
        directory::Directory,
    },
};

use super::{evaluate, parse, run};

pub fn bench_all(runs: RunsInfo, tools: ToolsInfo, output: PathBuf, timeout: Option<u64>) {
    let runner = run::Runner::new(
        &runs,
        &tools,
        timeout.map(Duration::from_secs),
        output.clone(),
    );
    let parser = parse::Parser::new(&runs, &tools, output.clone());
    let evaluator = evaluate::Evaluator::new(&runs, output.clone());

    let total_count = run_count(&runs.runs);
    println!(
        "Evaluating tools on benchmarks. Total run count: {}",
        total_count
    );

    let roots_tools = runs
        .runs
        .runs
        .iter()
        .flat_map(|run| run.roots.iter().cartesian_product(run.tools.iter()))
        .enumerate();

    for (count, (benchmark, tool)) in roots_tools {
        println!(
            "{}/{}: Processing configuration {} on {}",
            count + 1,
            total_count,
            tool,
            benchmark.display()
        );

        let directory = Directory::new(&output, benchmark, tool);
        runner.run_one(&directory);
        parser.parse_one(&directory);
        evaluator.evaluate_one(&directory);
    }

    println!("Evaluation done");

    summarize::make_summary(&runs, output);
    println!("Summarization done");
}
