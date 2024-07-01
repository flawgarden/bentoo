use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    path::{Path, PathBuf},
    time::Duration,
};

use itertools::Itertools;
use serde::Serialize;

use crate::{
    command::compare::evaluate_tool,
    reference::{
        taxonomy::{Taxonomy, TaxonomyVersion},
        truth::{self, CWEs, Kind, ToolResults, TruthResults},
    },
    run::{
        description::{
            runs::{Runs, RunsInfo},
            tools::Tool,
        },
        directory::Directory,
        metadata::{Metadata, Status},
    },
    util,
};

use super::compare::{MatchCard, MinimalMatchCard, ToolResultsCard};

#[derive(Debug, PartialEq, Serialize)]
pub struct SummaryRatios {
    true_positive_count: i64,
    false_positive_count: i64,
    true_positive_rate: f64,
    false_positive_rate: f64,
    recall: f64,
    precision: f64,
    f1_score: f64,
}

impl SummaryRatios {
    pub fn from_stats(
        true_positive_count: i64,
        false_positive_count: i64,
        ground_truth_positive_count: i64,
        ground_truth_negative_count: i64,
    ) -> Self {
        let false_negative_count = ground_truth_positive_count - true_positive_count;
        let true_positive_rate =
            util::round_dp3(true_positive_count as f64 / ground_truth_positive_count as f64);
        let false_positive_rate =
            util::round_dp3(false_positive_count as f64 / ground_truth_negative_count as f64);
        let recall =
            util::round_dp3(true_positive_count as f64 / ground_truth_positive_count as f64);
        let precision = util::round_dp3(
            true_positive_count as f64 / (true_positive_count + false_positive_count) as f64,
        );
        let f1_score = util::round_dp3(
            true_positive_count as f64
                / (true_positive_count as f64
                    + (false_positive_count as f64 + false_negative_count as f64) / 2_f64),
        );
        Self {
            true_positive_count,
            false_positive_count,
            true_positive_rate,
            false_positive_rate,
            f1_score,
            recall,
            precision,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct SummaryStats {
    at_least_one_file_with_cwe_match: u64,
    at_least_one_file_with_cwe_1000_match: u64,
    at_least_one_file_without_cwe_match: u64,
    at_least_one_region_with_cwe_match: u64,
    at_least_one_region_with_cwe_1000_match: u64,
    at_least_one_region_without_cwe_match: u64,
}
#[derive(Debug, PartialEq, Serialize)]
pub struct SummaryCard {
    at_least_one_file_with_cwe_match: SummaryRatios,
    at_least_one_file_with_cwe_1000_match: SummaryRatios,
    at_least_one_file_without_cwe_match: SummaryRatios,
    at_least_one_region_with_cwe_match: SummaryRatios,
    at_least_one_region_with_cwe_1000_match: SummaryRatios,
    at_least_one_region_without_cwe_match: SummaryRatios,
    ground_truth_negative_count: u64,
    ground_truth_positive_count: u64,
    truth_positive_cwe_match_count: u64,
    truth_positive_cwe_1000_match_count: u64,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct NamedSummaryCard {
    name: String,

    #[serde(flatten)]
    summary: SummaryCard,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ToolSummaryCard {
    tool: Tool,
    total_time: Duration,
    failed: usize,
    timeouts: usize,
    total: usize,
    runs_summary: SummaryCard,
    cwes_summary: Vec<NamedSummaryCard>,
    cwes_1000_summary: Vec<NamedSummaryCard>,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ToolsSummaryCard {
    summaries: Vec<ToolSummaryCard>,
}

struct SummarizedMetadata {
    time: Duration,
    failed: usize,
    timeouts: usize,
    total: usize,
}

pub struct Summarizer<'s> {
    runs: &'s Runs,
    results_root: PathBuf,
    taxonomy: Taxonomy,
}

impl<'s> Summarizer<'s> {
    pub fn new(runs: &'s Runs, results_root: PathBuf) -> Self {
        Summarizer {
            runs,
            results_root,
            taxonomy: Taxonomy::from_known_version(&TaxonomyVersion::default()),
        }
    }

    fn collect_cards(&self) -> HashMap<Tool, ToolResultsCard> {
        let cards = self
            .runs
            .runs
            .iter()
            .flat_map(|run| run.roots.iter().cartesian_product(run.tools.iter()))
            .filter_map(|(root, tool)| {
                let directory = Directory::new(&self.results_root, root, tool);
                let metadata = directory.metadata_read();
                if metadata.is_none() {
                    println!(
                        "Summarizer: No metadata for {} on {}, skipping",
                        directory.tool,
                        directory.benchmark.display()
                    );
                    None
                } else if !metadata.unwrap().evaluated {
                    println!(
                        "Summarizer: {} on {} hasn't been evaluated, skipping",
                        directory.tool,
                        directory.benchmark.display()
                    );
                    let truth = TruthResults::try_from(directory.truth_path().as_path()).unwrap();
                    let tool_result = ToolResults {
                        name: String::new(),
                        results: vec![],
                    };
                    let faux_evaluate = evaluate_tool(&truth, &tool_result, None);
                    Some((tool.clone(), faux_evaluate.result))
                } else {
                    let file_name = self.make_file_name(root, tool, "json");
                    let tool_card = ToolResultsCard::try_from(Path::new(&file_name)).ok()?;
                    Some((tool.clone(), tool_card.result))
                }
            })
            .into_group_map()
            .into_iter()
            .map(|(tool, tool_cards)| {
                (
                    tool,
                    ToolResultsCard {
                        result: tool_cards.into_iter().flatten().collect(),
                    },
                )
            })
            .collect();

        cards
    }

    fn collect_metadata(&self) -> HashMap<Tool, SummarizedMetadata> {
        let metadata = self
            .runs
            .runs
            .iter()
            .flat_map(|run| run.roots.iter().cartesian_product(run.tools.iter()))
            .map(|(root, tool)| {
                let file_name = self.make_file_name(root, tool, "metadata");
                let file = File::open(file_name).unwrap();
                let tool_metadata = Metadata::from_file(&file);
                (tool.clone(), tool_metadata)
            })
            .into_group_map()
            .into_iter()
            .map(|(tool, metadatas)| {
                let mut time = Duration::new(0, 0);
                let mut failed: usize = 0;
                let mut timeouts: usize = 0;
                for metadata in metadatas.iter() {
                    time += metadata.time;
                    if !metadata.evaluated {
                        failed += 1;
                    }
                    if metadata.status == Status::Timeout {
                        timeouts += 1;
                    }
                }
                (
                    tool,
                    SummarizedMetadata {
                        time,
                        failed,
                        timeouts,
                        total: metadatas.len(),
                    },
                )
            })
            .collect();

        metadata
    }

    fn make_file_name(&self, root: &PathBuf, tool: &Tool, extension: &str) -> String {
        let parent = Path::new(root);
        let file_name = format!("{}_{}.{}", tool.script, tool.config, extension);
        let mut absolute_file_name = self.results_root.clone();
        absolute_file_name.push(parent);
        absolute_file_name.push(file_name);
        absolute_file_name
            .into_os_string()
            .into_string()
            .ok()
            .unwrap()
    }

    fn summarize_match_card_vec<'a, T, P>(
        minimal_match_cards: Vec<T>,
        match_cards: Vec<Vec<P>>,
    ) -> SummaryCard
    where
        T: AsRef<MinimalMatchCard<'a>>,
        P: AsRef<MatchCard<'a>>,
    {
        let (fail_results, pass_results): (Vec<_>, Vec<_>) = minimal_match_cards
            .into_iter()
            .partition(|card| card.as_ref().0.expected_kind == truth::Kind::Fail);
        let calc_stat = |results: Vec<T>| {
            let mut at_least_one_file_with_cwe_match: u64 = 0;
            let mut at_least_one_file_with_cwe_1000_match: u64 = 0;
            let mut at_least_one_file_without_cwe_match: u64 = 0;
            let mut at_least_one_region_with_cwe_match: u64 = 0;
            let mut at_least_one_region_with_cwe_1000_match: u64 = 0;
            let mut at_least_one_region_without_cwe_match: u64 = 0;
            for card in results.iter() {
                at_least_one_file_with_cwe_match +=
                    (card.as_ref().1.at_least_one_file_match && card.as_ref().1.cwe_match) as u64;
                at_least_one_file_with_cwe_1000_match += (card.as_ref().1.at_least_one_file_match
                    && card.as_ref().1.cwe_1000_match)
                    as u64;
                at_least_one_file_without_cwe_match +=
                    card.as_ref().1.at_least_one_file_match as u64;
                at_least_one_region_with_cwe_match +=
                    (card.as_ref().1.at_least_one_region_match && card.as_ref().1.cwe_match) as u64;
                at_least_one_region_with_cwe_1000_match +=
                    (card.as_ref().1.at_least_one_region_match && card.as_ref().1.cwe_1000_match)
                        as u64;
                at_least_one_region_without_cwe_match +=
                    card.as_ref().1.at_least_one_region_match as u64;
            }
            SummaryStats {
                at_least_one_file_with_cwe_match,
                at_least_one_file_with_cwe_1000_match,
                at_least_one_file_without_cwe_match,
                at_least_one_region_with_cwe_match,
                at_least_one_region_with_cwe_1000_match,
                at_least_one_region_without_cwe_match,
            }
        };
        let ground_truth_positive_count = fail_results.len();
        let ground_truth_negative_count = pass_results.len();
        let mut truth_positive_cwe_match_count: u64 = 0;
        let mut truth_positive_cwe_1000_match_count: u64 = 0;
        for max_cards in match_cards.iter() {
            truth_positive_cwe_match_count += max_cards.iter().any(|card| {
                card.as_ref().0.expected_kind == Kind::Fail
                    && card.as_ref().1.minimal_match.cwe_match
            }) as u64;
            truth_positive_cwe_1000_match_count += max_cards.iter().any(|card| {
                card.as_ref().0.expected_kind == Kind::Fail
                    && card.as_ref().1.minimal_match.cwe_1000_match
            }) as u64;
        }

        let fail_stat = calc_stat(fail_results);
        let pass_stat = calc_stat(pass_results);
        let calc_summary_ratio = |true_positive_count, false_positive_count| {
            SummaryRatios::from_stats(
                true_positive_count as i64,
                false_positive_count as i64,
                ground_truth_positive_count as i64,
                ground_truth_negative_count as i64,
            )
        };
        SummaryCard {
            at_least_one_file_with_cwe_match: calc_summary_ratio(
                fail_stat.at_least_one_file_with_cwe_match,
                pass_stat.at_least_one_file_with_cwe_match,
            ),
            at_least_one_file_with_cwe_1000_match: calc_summary_ratio(
                fail_stat.at_least_one_file_with_cwe_1000_match,
                pass_stat.at_least_one_file_with_cwe_1000_match,
            ),
            at_least_one_file_without_cwe_match: calc_summary_ratio(
                fail_stat.at_least_one_file_without_cwe_match,
                pass_stat.at_least_one_file_without_cwe_match,
            ),
            at_least_one_region_with_cwe_match: calc_summary_ratio(
                fail_stat.at_least_one_region_with_cwe_match,
                pass_stat.at_least_one_region_with_cwe_match,
            ),
            at_least_one_region_with_cwe_1000_match: calc_summary_ratio(
                fail_stat.at_least_one_region_with_cwe_1000_match,
                pass_stat.at_least_one_region_with_cwe_1000_match,
            ),
            at_least_one_region_without_cwe_match: calc_summary_ratio(
                fail_stat.at_least_one_region_without_cwe_match,
                pass_stat.at_least_one_region_without_cwe_match,
            ),
            ground_truth_negative_count: ground_truth_negative_count as u64,
            ground_truth_positive_count: ground_truth_positive_count as u64,
            truth_positive_cwe_match_count,
            truth_positive_cwe_1000_match_count,
        }
    }

    fn summarize_tool_results(tool_result: &ToolResultsCard) -> SummaryCard {
        let (minimal_matches, matches) = tool_result
            .result
            .iter()
            .map(|result| {
                (
                    MinimalMatchCard(&result.expected_result, &result.max_minimal_match),
                    result
                        .max_match
                        .iter()
                        .map(|match_result| MatchCard(&result.expected_result, match_result))
                        .collect(),
                )
            })
            .unzip();
        Summarizer::summarize_match_card_vec(minimal_matches, matches)
    }

    fn summarize_tool_results_by_cwe(tool_result: &ToolResultsCard) -> Vec<NamedSummaryCard> {
        tool_result
            .result
            .iter()
            .into_group_map_by(|result| result.expected_result.expected_cwe.clone())
            .into_iter()
            .map(|(cwe, results)| {
                let (minimal_matches, matches) = results
                    .iter()
                    .map(|result| {
                        (
                            MinimalMatchCard(&result.expected_result, &result.max_minimal_match),
                            result
                                .max_match
                                .iter()
                                .map(|match_result| {
                                    MatchCard(&result.expected_result, match_result)
                                })
                                .collect(),
                        )
                    })
                    .unzip();
                NamedSummaryCard {
                    name: format!("{}", cwe),
                    summary: Summarizer::summarize_match_card_vec(minimal_matches, matches),
                }
            })
            .collect()
    }

    fn summarize_tool_results_by_cwe_1000(
        &self,
        tool_result: &ToolResultsCard,
    ) -> Vec<NamedSummaryCard> {
        tool_result
            .result
            .iter()
            .filter_map(|result| {
                let cwes_1000 = result
                    .expected_result
                    .expected_cwe
                    .cwes
                    .iter()
                    .map(|cwe| match self.taxonomy.to_cwe_1000(cwe) {
                        Some(cwes_1000) => cwes_1000.clone(),
                        None => HashSet::default(),
                    })
                    .reduce(|x, y| x.union(&y).cloned().collect());
                match cwes_1000 {
                    Some(cwes_1000) => {
                        if cwes_1000.is_empty() {
                            None
                        } else {
                            let cwes_1000_list = cwes_1000.iter().cloned().collect_vec();
                            Some((result, cwes_1000_list))
                        }
                    }
                    None => None,
                }
            })
            .into_group_map_by(|(_result, cwe_1000)| cwe_1000.clone())
            .into_iter()
            .map(|(cwe, results)| {
                (
                    cwe,
                    results
                        .into_iter()
                        .map(|(result, _)| result)
                        .collect::<Vec<_>>(),
                )
            })
            .map(|(cwe, results)| {
                let (minimal_matches, matches) = results
                    .iter()
                    .map(|result| {
                        (
                            MinimalMatchCard(&result.expected_result, &result.max_minimal_match),
                            result
                                .max_match
                                .iter()
                                .map(|match_result| {
                                    MatchCard(&result.expected_result, match_result)
                                })
                                .collect(),
                        )
                    })
                    .unzip();
                NamedSummaryCard {
                    name: format!("{}", CWEs { cwes: cwe.clone() }),
                    summary: Summarizer::summarize_match_card_vec(minimal_matches, matches),
                }
            })
            .collect()
    }

    pub fn summarize(&self) -> ToolsSummaryCard {
        let cards = self.collect_cards();
        let metadata = self.collect_metadata();
        let summary = cards
            .into_iter()
            .map(|(tool, card)| ToolSummaryCard {
                tool: tool.clone(),
                total_time: metadata[&tool].time,
                failed: metadata[&tool].failed,
                timeouts: metadata[&tool].timeouts,
                total: metadata[&tool].total,
                runs_summary: Summarizer::summarize_tool_results(&card),
                cwes_summary: Summarizer::summarize_tool_results_by_cwe(&card),
                cwes_1000_summary: self.summarize_tool_results_by_cwe_1000(&card),
            })
            .collect();
        ToolsSummaryCard { summaries: summary }
    }
}

pub fn make_summary(runs: &RunsInfo, output: PathBuf) {
    let results_path = fs::canonicalize(output).unwrap();

    let summarizer = Summarizer::new(&runs.runs, results_path.clone());
    let summary = summarizer.summarize();

    let summary_filename = "summary.json";
    let summary_path = results_path.join(summary_filename);

    let summary_file = File::create(summary_path).unwrap();
    serde_json::to_writer_pretty(summary_file, &summary).expect("error: failure to write summary");
}
