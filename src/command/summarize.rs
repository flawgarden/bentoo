use std::{
    collections::HashMap,
    fs::{self, File},
    path::{Path, PathBuf},
    time::Duration,
};

use csv::Writer;
use itertools::Itertools;
use serde::Serialize;

use crate::{
    command::compare::evaluate_tool,
    reference::{
        taxonomy::{Taxonomy, TaxonomyVersion},
        truth::{self, Kind, ToolResults, TruthResults},
    },
    run::{
        description::{
            runs::{Runs, RunsInfo},
            tools::Tool,
        },
        directory::Directory,
        metadata::Metadata,
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

#[derive(Debug, Serialize)]
pub struct SummaryMatchesCard {
    pub matches: Vec<bool>,
}

pub struct ToolSummaryMatchesCard {
    pub tool: Tool,
    pub summary: SummaryMatchesCard,
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
    runs_summary: SummaryCard,
    cwes_summary: Vec<NamedSummaryCard>,
    cwes_1000_summary: Vec<NamedSummaryCard>,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ToolsSummaryCard {
    summaries: Vec<ToolSummaryCard>,
}

pub struct ToolsSummaryMatchesCard {
    pub summaries: Vec<ToolSummaryMatchesCard>,
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

    fn collect_metadata(&self) -> HashMap<Tool, Duration> {
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
                let mut total_time = Duration::new(0, 0);
                for metadata in metadatas {
                    total_time += metadata.time;
                }
                (tool, total_time)
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

    fn summarize_tool_results_matches(tool_result: &ToolResultsCard) -> SummaryMatchesCard {
        let matches = tool_result
            .result
            .iter()
            .map(|result| {
                let at_least_one_file_with_cwe_1000_match =
                    result.max_minimal_match.at_least_one_file_match
                        && result.max_minimal_match.cwe_1000_match;
                match result.expected_result.expected_kind {
                    Kind::Fail => at_least_one_file_with_cwe_1000_match,
                    // Kind::Pass => !at_least_one_file_with_cwe_1000_match,
                    Kind::Pass => false,
                }
            })
            .collect();
        SummaryMatchesCard { matches }
    }

    fn summarize_tool_results_by_cwe(tool_result: &ToolResultsCard) -> Vec<NamedSummaryCard> {
        tool_result
            .result
            .iter()
            .into_group_map_by(|result| result.expected_result.expected_cwe)
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
                    name: format!("CWE-{}", cwe),
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
                match self.taxonomy.to_cwe_1000(&truth::CWE {
                    cwe: result.expected_result.expected_cwe,
                }) {
                    Some(cwes_1000) => {
                        if cwes_1000.is_empty() {
                            None
                        } else {
                            let mut cwes_1000_list = cwes_1000.iter().collect_vec();
                            cwes_1000_list.sort();
                            Some((result, *cwes_1000_list.iter().next_back().unwrap()))
                        }
                    }
                    None => None,
                }
            })
            .into_group_map_by(|(_result, cwe_1000)| cwe_1000.cwe)
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
                    name: format!("CWE-{}", cwe),
                    summary: Summarizer::summarize_match_card_vec(minimal_matches, matches),
                }
            })
            .collect()
    }

    pub fn summarize(&self) -> (ToolsSummaryCard, ToolsSummaryMatchesCard) {
        let cards = self.collect_cards();
        let metadata = self.collect_metadata();
        let (tools_summary, matches_smummary) = cards
            .into_iter()
            .map(|(tool_id, card)| {
                (
                    ToolSummaryCard {
                        tool: tool_id.clone(),
                        total_time: metadata[&tool_id],
                        runs_summary: Summarizer::summarize_tool_results(&card),
                        cwes_summary: Summarizer::summarize_tool_results_by_cwe(&card),
                        cwes_1000_summary: self.summarize_tool_results_by_cwe_1000(&card),
                    },
                    ToolSummaryMatchesCard {
                        tool: tool_id,
                        summary: Summarizer::summarize_tool_results_matches(&card),
                    },
                )
            })
            .unzip();
        (
            ToolsSummaryCard {
                summaries: tools_summary,
            },
            ToolsSummaryMatchesCard {
                summaries: matches_smummary,
            },
        )
    }
}

pub fn make_summary(runs: &RunsInfo, output: PathBuf) {
    let results_path = fs::canonicalize(output).unwrap();

    let summarizer = Summarizer::new(&runs.runs, results_path.clone());
    let (tools_summary, matches_summary) = summarizer.summarize();

    let tools_summary_filename = "summary.json";
    let tools_summary_path = results_path.join(tools_summary_filename);

    let tools_summary_file = File::create(tools_summary_path).unwrap();
    serde_json::to_writer_pretty(tools_summary_file, &tools_summary)
        .expect("error: failure to write summary");

    let matches_summary_filename = "summary.csv";
    let matches_summary_path = results_path.join(matches_summary_filename);

    let mut wrt =
        Writer::from_path(matches_summary_path).expect("error: failure to write matches summary");
    for tool_matches_summary in matches_summary.summaries {
        wrt.write_field(format!("{}", tool_matches_summary.tool))
            .expect("error: failure during matches summary serialization");
        wrt.write_record(
            tool_matches_summary
                .summary
                .matches
                .iter()
                .map(bool::to_string),
        )
        .expect("error: failure during matches summary serialization");
    }
}
