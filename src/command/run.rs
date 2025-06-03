use std::{
    fs,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

use home::home_dir;
use itertools::Itertools;

use crate::{
    run::{
        description::{run_count, runs::RunsInfo, tools::ToolsInfo},
        directory::Directory,
        metadata::{Metadata, Status},
    },
    util::{copy_dir, ChildWait},
};

pub struct Runner<'a> {
    runs: &'a RunsInfo,
    tools: &'a ToolsInfo,
    timeout: Option<Duration>,
    output: PathBuf,
    isolate_root: bool,
}

impl<'a> Runner<'a> {
    pub fn new(
        runs: &'a RunsInfo,
        tools: &'a ToolsInfo,
        timeout: Option<Duration>,
        output: PathBuf,
        isolate_root: bool,
    ) -> Self {
        fs::create_dir_all(home_dir().unwrap().join(".bentoo")).unwrap();
        Runner {
            runs,
            tools,
            timeout,
            output,
            isolate_root,
        }
    }

    pub fn run_one(&self, directory: &Directory) {
        let (script, config) = self.tools.tools.get(directory.tool);

        let benchmark_path = self.runs.root.join(directory.benchmark);
        let output_path = self.output.join(directory.benchmark);

        if benchmark_path.join("truth.sarif").exists() {
            // TODO: find a better place for this
            std::fs::copy(
                benchmark_path.join("truth.sarif"),
                output_path.join("truth.sarif"),
            )
            .unwrap();
        } else {
            println!(
                "Runner: Warning: Could not find truth.sarif in {}",
                benchmark_path.display()
            );
        }

        if let Some(metadata) = directory.metadata_read() {
            if metadata.status == Status::ScriptError {
                println!("Runner: Run script failed to run during previous run, retrying");
            } else if metadata.exit_code != 0 {
                println!("Runner: Previous run exited with non-zero exit code, retrying");
            } else {
                println!("Runner: Previous run was OK, skipping");
                return;
            }
        } else {
            println!("Runner: No metadata found for the run, running");
        }

        let isolator_tmp = tempfile::TempDir::new_in(home_dir().unwrap().join(".bentoo")).unwrap();
        let benchmark_tmp = if self.isolate_root {
            copy_dir(&self.runs.root, isolator_tmp.path()).unwrap();
            isolator_tmp
                .path()
                .join(benchmark_path.strip_prefix(&self.runs.root).unwrap())
        } else {
            copy_dir(&benchmark_path, isolator_tmp.path()).unwrap();
            isolator_tmp.keep()
        };

        let script = self.tools.root.join(&script.script);

        let child = Command::new(script)
            .arg(benchmark_tmp)
            .args(config.args.split_whitespace())
            .stdout(directory.out_file_write())
            .stderr(directory.err_file_write())
            .spawn();

        let mut metadata = Metadata::default();

        if let Err(error) = child {
            eprintln!("Failed to execute runner script: {}", error);
            metadata.status = Status::ScriptError;
        } else {
            let mut child = child.unwrap();
            let now = Instant::now();

            match self.timeout {
                Some(timeout) => {
                    let wait_result = child.wait_timeout(timeout);
                    if wait_result.is_none() {
                        eprintln!("Runner script killed due to timeout");
                        metadata.status = Status::Timeout;
                    }
                }
                None => {
                    child.wait().expect("Error: failure in wait()");
                }
            }

            let time = now.elapsed();

            metadata.time = time;
            metadata.exit_code = child.wait().unwrap().into_raw();
        }

        directory.metadata_write(&metadata);
    }

    pub fn run_all(&self) {
        std::fs::create_dir_all(&self.output).unwrap();

        let total_count = run_count(&self.runs.runs);
        println!(
            "Running tools on benchmarks. Total run count: {}",
            total_count
        );

        let roots_tools = self
            .runs
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

            let directory = Directory::new(&self.output, benchmark, tool);
            self.run_one(&directory);
        }

        println!("Running done. Runs output is in {}", self.output.display());
    }
}
