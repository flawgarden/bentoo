use bentoo::command::{bench, compare, convert, evaluate, parse, run, summarize, template};
use bentoo::reference::truth;
use bentoo::run::description::{runs::RunsInfo, tools::ToolsInfo};

use clap::{arg, Parser, Subcommand};

use std::path::{Path, PathBuf};

use std::time::Duration;

#[derive(Parser)]
#[command(version)]
/// bentoo - SAST tool benchmarking infrastructure
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Convert supported formats into bentoo-sarif
    Convert {
        /// Format to convert, please refer to docs for info on supported formats
        format: String,
        /// File to convert, must adhere to the specified format
        file: PathBuf,
    },
    /// Compare tool result against truth
    Compare {
        /// Ground truth to compare against
        truth: PathBuf,
        /// Tool's output to compare
        tool: PathBuf,
        #[arg(short, long, default_value_t = false)]
        /// Produce a detailed report
        detailed: bool,
    },
    /// Generate a runs template for given project
    Template {
        #[arg(short, long)]
        /// Path to a tools spec to populate the template
        tools: Option<PathBuf>,
        /// Root of benchmark to generate the template for
        root: PathBuf,
    },
    /// Run tools on benchmarks and collect output
    Run {
        #[arg(short, long)]
        /// Tools spec to use for the run
        tools: PathBuf,
        #[arg(short, long)]
        /// Runs spec to use, used tools must be listed in the tools spec
        runs: PathBuf,
        /// Directory to use for output
        output: PathBuf,
        #[arg(long)]
        /// Timeout for each run of each tool in seconds
        timeout: Option<u64>,
    },
    /// Parse tools' output for further evaluation
    Parse {
        #[arg(short, long)]
        /// Tools spec to use
        tools: PathBuf,
        #[arg(short, long)]
        /// Runs spec to use, used tools must be listed in the tools spec
        runs: PathBuf,
        /// Output directory to parse
        output: PathBuf,
    },
    /// Generate tools cards by comparing against truth files
    Evaluate {
        #[arg(short, long)]
        /// Runs spec to use, used tools must be listed in the tools spec
        runs: PathBuf,
        /// Output directory to parse
        output: PathBuf,
        #[arg(short, long, default_value_t = false)]
        /// Produce a detailed report
        detailed: bool,
    },
    /// Calculate statistics and metrics from tools cards
    Summarize {
        #[arg(short, long)]
        /// Runs spec to use, used tools must be listed in the tools spec
        runs: PathBuf,
        /// Directory used for output
        output: PathBuf,
    },
    /// One-shot command to run, parse, evaluate and summarize
    Bench {
        #[arg(short, long)]
        /// Tools spec to use for the run
        tools: PathBuf,
        #[arg(short, long)]
        /// Runs spec to use, used tools must be listed in the tools spec
        runs: PathBuf,
        /// Directory to use for output
        output: PathBuf,
        #[arg(long)]
        /// Timeout for each run of each tool in seconds
        timeout: Option<u64>,
        #[arg(long, default_value_t = false)]
        /// Produce a detailed report
        detailed: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Convert { format, file } => {
            let sarif = convert::convert_from(format, file);
            println!("{}", serde_json::to_string_pretty(&sarif).unwrap())
        }
        Command::Compare {
            truth,
            tool,
            detailed,
        } => {
            let truth = truth::TruthResults::try_from(Path::new(&truth))
                .expect("Could not parse truth file");
            let tool = truth::ToolResults::try_from(Path::new(&tool))
                .expect("Could not parse tool result");
            let card = compare::evaluate_tool(&truth, &tool, None, detailed);
            println!("{}", serde_json::to_string_pretty(&card).unwrap());
        }
        Command::Template { tools, root } => {
            let runs = template::make_runs_template(root, tools);
            println!("{}", toml::to_string_pretty(&runs).unwrap());
        }
        Command::Run {
            tools,
            runs,
            output,
            timeout,
        } => {
            let runs = RunsInfo::new(runs);
            let tools = ToolsInfo::new(tools);
            run::Runner::new(&runs, &tools, timeout.map(Duration::from_secs), output).run_all();
        }
        Command::Parse {
            tools,
            runs,
            output,
        } => {
            let runs = RunsInfo::new(runs);
            let tools = ToolsInfo::new(tools);
            parse::Parser::new(&runs, &tools, output).parse_all();
        }
        Command::Evaluate {
            runs,
            output,
            detailed,
        } => {
            let runs = RunsInfo::new(runs);
            evaluate::Evaluator::new(&runs, output).evaluate_all(detailed);
        }
        Command::Summarize {
            runs,
            output: results,
        } => {
            let runs = RunsInfo::new(runs);
            summarize::make_summary(&runs, results);
        }
        Command::Bench {
            tools,
            runs,
            output,
            timeout,
            detailed,
        } => {
            let runs = RunsInfo::new(runs);
            let tools = ToolsInfo::new(tools);
            bench::bench_all(runs, tools, output, timeout, detailed);
        }
    }
}
