use std::{
    collections::{BTreeMap, HashSet},
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
        report_config::ReportConfig,
    },
    util,
};

use super::compare::{MatchCard, MinimalMatchCard, ToolResultCard, ToolResultsCard};

enum SummaryNode {
    Internal {
        children: BTreeMap<String, SummaryNode>,
    },
    Leaf {
        summary: Box<ToolSummaryCard>,
    },
}

impl SummaryNode {
    fn try_internal_mut(&mut self) -> Option<&mut BTreeMap<String, SummaryNode>> {
        match self {
            SummaryNode::Internal { children } => Some(children),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
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

    pub fn union(
        &self,
        other: &Self,
        ground_truth_positive_count: i64,
        ground_truth_negative_count: i64,
    ) -> Self {
        let true_positive_count = self.true_positive_count + other.true_positive_count;
        let false_positive_count = self.false_positive_count + other.false_positive_count;
        Self::from_stats(
            true_positive_count,
            false_positive_count,
            ground_truth_positive_count,
            ground_truth_negative_count,
        )
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct SummaryStats {
    at_least_one_file_with_rule_id_match: i64,
    at_least_one_file_with_cwe_match: i64,
    at_least_one_file_with_cwe_1000_match: i64,
    at_least_one_file_without_cwe_match: i64,
    at_least_one_region_with_cwe_match: i64,
    at_least_one_region_with_rule_id_match: i64,
    at_least_one_region_with_cwe_1000_match: i64,
    at_least_one_region_without_cwe_match: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SummaryCard {
    at_least_one_file_with_rule_id_match: SummaryRatios,
    at_least_one_file_with_cwe_match: SummaryRatios,
    at_least_one_file_with_cwe_1000_match: SummaryRatios,
    at_least_one_file_without_cwe_match: SummaryRatios,
    at_least_one_region_with_rule_id_match: SummaryRatios,
    at_least_one_region_with_cwe_match: SummaryRatios,
    at_least_one_region_with_cwe_1000_match: SummaryRatios,
    at_least_one_region_without_cwe_match: SummaryRatios,
    ground_truth_negative_count: i64,
    ground_truth_positive_count: i64,
    truth_positive_cwe_match_count: i64,
    truth_positive_cwe_1000_match_count: i64,
}

impl SummaryCard {
    pub fn union<'a>(&'a self, other: &'a Self) -> Self {
        let ground_truth_positive_count =
            self.ground_truth_positive_count + other.ground_truth_positive_count;
        let ground_truth_negative_count =
            self.ground_truth_negative_count + other.ground_truth_negative_count;
        let truth_positive_cwe_match_count =
            self.truth_positive_cwe_match_count + other.truth_positive_cwe_match_count;
        let truth_positive_cwe_1000_match_count =
            self.truth_positive_cwe_1000_match_count + other.truth_positive_cwe_1000_match_count;
        macro_rules! union_ratios {
            ($a_card:expr, $b_card:expr, $ratio:ident) => {
                $a_card.$ratio.union(
                    &$b_card.$ratio,
                    ground_truth_positive_count,
                    ground_truth_negative_count,
                )
            };
        }
        let at_least_one_file_with_rule_id_match =
            union_ratios!(self, other, at_least_one_file_with_rule_id_match);
        let at_least_one_file_with_cwe_match =
            union_ratios!(self, other, at_least_one_file_with_cwe_match);
        let at_least_one_file_with_cwe_1000_match =
            union_ratios!(self, other, at_least_one_file_with_cwe_1000_match);
        let at_least_one_file_without_cwe_match =
            union_ratios!(self, other, at_least_one_file_without_cwe_match);
        let at_least_one_region_with_cwe_match =
            union_ratios!(self, other, at_least_one_region_with_cwe_match);
        let at_least_one_region_with_rule_id_match =
            union_ratios!(self, other, at_least_one_region_with_rule_id_match);
        let at_least_one_region_with_cwe_1000_match =
            union_ratios!(self, other, at_least_one_region_with_cwe_1000_match);
        let at_least_one_region_without_cwe_match =
            union_ratios!(self, other, at_least_one_region_without_cwe_match);

        Self {
            at_least_one_file_with_cwe_match,
            at_least_one_file_with_cwe_1000_match,
            at_least_one_file_without_cwe_match,
            at_least_one_region_with_cwe_match,
            at_least_one_region_with_cwe_1000_match,
            at_least_one_region_without_cwe_match,
            ground_truth_positive_count,
            ground_truth_negative_count,
            truth_positive_cwe_match_count,
            truth_positive_cwe_1000_match_count,
            at_least_one_file_with_rule_id_match,
            at_least_one_region_with_rule_id_match,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NamedSummaryCard {
    name: String,

    #[serde(flatten)]
    summary: SummaryCard,
}

impl NamedSummaryCard {
    fn union(&self, other: &Self) -> Self {
        assert!(self.name == other.name);
        Self {
            name: self.name.clone(),
            summary: self.summary.union(&other.summary),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
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

impl ToolSummaryCard {
    fn union(&self, other: &Self) -> Self {
        assert!(self.tool == other.tool);

        let mut cwes_map: BTreeMap<String, Vec<NamedSummaryCard>> = BTreeMap::new();
        let mut cwes_1000_map: BTreeMap<String, Vec<NamedSummaryCard>> = BTreeMap::new();

        fn collect_summaries(
            summaries: &[NamedSummaryCard],
            cwes_map: &mut BTreeMap<String, Vec<NamedSummaryCard>>,
        ) {
            for summary in summaries.iter() {
                let vec = cwes_map.entry(summary.name.clone()).or_default();
                vec.push(summary.clone());
            }
        }

        collect_summaries(&self.cwes_summary, &mut cwes_map);
        collect_summaries(&other.cwes_summary, &mut cwes_map);
        collect_summaries(&self.cwes_1000_summary, &mut cwes_1000_map);
        collect_summaries(&other.cwes_1000_summary, &mut cwes_1000_map);

        let mut cwes_summary = vec![];
        let mut cwes_1000_summary = vec![];

        for (_, summaries) in cwes_map {
            let summary = summaries
                .into_iter()
                .reduce(|a_summary, b_summary| a_summary.union(&b_summary))
                .unwrap();
            cwes_summary.push(summary);
        }

        for (_, summaries) in cwes_1000_map {
            let summary = summaries
                .into_iter()
                .reduce(|a_summary, b_summary| a_summary.union(&b_summary))
                .unwrap();
            cwes_1000_summary.push(summary);
        }

        Self {
            tool: self.tool.clone(),
            total_time: self.total_time + other.total_time,
            failed: self.failed + other.failed,
            timeouts: self.timeouts + other.timeouts,
            total: self.total + other.total,
            runs_summary: self.runs_summary.union(&other.runs_summary),
            cwes_summary,
            cwes_1000_summary,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ToolsSummaryCard {
    summaries: Vec<ToolSummaryCard>,
}

pub struct Summarizer<'s> {
    runs: &'s Runs,
    results_root: PathBuf,
    taxonomy: Taxonomy,
    summary_root: SummaryNode,
}

impl<'s> Summarizer<'s> {
    pub fn new(runs: &'s Runs, results_root: PathBuf) -> Self {
        Summarizer {
            runs,
            results_root,
            taxonomy: Taxonomy::from_known_version(&TaxonomyVersion::default()),
            summary_root: SummaryNode::Internal {
                children: BTreeMap::new(),
            },
        }
    }

    fn summarize_tool(
        &self,
        tool: &Tool,
        md: &Metadata,
        card: &ToolResultsCard,
    ) -> ToolSummaryCard {
        ToolSummaryCard {
            tool: tool.clone(),
            total_time: md.time,
            failed: if md.evaluated { 0 } else { 1 },
            timeouts: if md.status == Status::Timeout { 1 } else { 0 },
            total: 1,
            runs_summary: Summarizer::summarize_tool_results(card),
            cwes_summary: Summarizer::summarize_tool_results_by_cwe(card),
            cwes_1000_summary: self.summarize_tool_results_by_cwe_1000(card),
        }
    }

    fn summarize_run(&mut self, root: &PathBuf, tool: &Tool) {
        let directory = Directory::new(&self.results_root, root, tool);
        let metadata = directory.metadata_read();
        if metadata.is_none() {
            println!(
                "Summarizer: No metadata for {} on {}, skipping",
                tool,
                root.display()
            );
            return;
        }

        let metadata = metadata.unwrap();

        let card = if metadata.evaluated {
            let filename = self.make_file_name(root, tool, "json");
            ToolResultsCard::try_from(Path::new(&filename))
                .ok()
                .unwrap()
        } else {
            println!(
                "Summarizer: {} on {} hasn't been evaluated, skipping",
                tool,
                root.display()
            );
            let truth = TruthResults::try_from(directory.truth_path().as_path()).unwrap();
            let tool_result = ToolResults {
                name: String::new(),
                results: vec![],
            };
            evaluate_tool(&truth, &tool_result, None, ReportConfig::default())
        };

        let summary = self.summarize_tool(tool, &metadata, &card);

        let mut node = &mut self.summary_root;
        for component in root.components() {
            let component = String::from(component.as_os_str().to_str().unwrap());
            let children = node.try_internal_mut().expect("Node must be internal");
            node = children.entry(component).or_insert(SummaryNode::Internal {
                children: BTreeMap::new(),
            });
        }

        if let Some(children) = node.try_internal_mut() {
            children.insert(
                format!("{}_{}", tool.script, tool.config),
                SummaryNode::Leaf {
                    summary: Box::new(summary),
                },
            );
        }
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
            let mut at_least_one_file_with_rule_id_match: i64 = 0;
            let mut at_least_one_file_with_cwe_match: i64 = 0;
            let mut at_least_one_file_with_cwe_1000_match: i64 = 0;
            let mut at_least_one_file_without_cwe_match: i64 = 0;
            let mut at_least_one_region_with_rule_id_match: i64 = 0;
            let mut at_least_one_region_with_cwe_match: i64 = 0;
            let mut at_least_one_region_with_cwe_1000_match: i64 = 0;
            let mut at_least_one_region_without_cwe_match: i64 = 0;
            for card in results.iter() {
                at_least_one_file_with_rule_id_match += (card.as_ref().1.at_least_one_file_match
                    && card.as_ref().1.rule_id_match)
                    as i64;
                at_least_one_file_with_cwe_match +=
                    (card.as_ref().1.at_least_one_file_match && card.as_ref().1.cwe_match) as i64;
                at_least_one_file_with_cwe_1000_match += (card.as_ref().1.at_least_one_file_match
                    && card.as_ref().1.cwe_1000_match)
                    as i64;
                at_least_one_file_without_cwe_match +=
                    card.as_ref().1.at_least_one_file_match as i64;
                at_least_one_region_with_rule_id_match +=
                    (card.as_ref().1.at_least_one_region_match && card.as_ref().1.rule_id_match)
                        as i64;
                at_least_one_region_with_cwe_match +=
                    (card.as_ref().1.at_least_one_region_match && card.as_ref().1.cwe_match) as i64;
                at_least_one_region_with_cwe_1000_match +=
                    (card.as_ref().1.at_least_one_region_match && card.as_ref().1.cwe_1000_match)
                        as i64;
                at_least_one_region_without_cwe_match +=
                    card.as_ref().1.at_least_one_region_match as i64;
            }
            SummaryStats {
                at_least_one_file_with_cwe_match,
                at_least_one_file_with_cwe_1000_match,
                at_least_one_file_without_cwe_match,
                at_least_one_region_with_cwe_match,
                at_least_one_region_with_cwe_1000_match,
                at_least_one_region_without_cwe_match,
                at_least_one_file_with_rule_id_match,
                at_least_one_region_with_rule_id_match,
            }
        };
        let ground_truth_positive_count = fail_results.len();
        let ground_truth_negative_count = pass_results.len();
        let mut truth_positive_cwe_match_count: i64 = 0;
        let mut truth_positive_cwe_1000_match_count: i64 = 0;
        for max_cards in match_cards.iter() {
            truth_positive_cwe_match_count += max_cards.iter().any(|card| {
                card.as_ref().0.expected_kind == Kind::Fail
                    && card.as_ref().1.minimal_match.cwe_match
            }) as i64;
            truth_positive_cwe_1000_match_count += max_cards.iter().any(|card| {
                card.as_ref().0.expected_kind == Kind::Fail
                    && card.as_ref().1.minimal_match.cwe_1000_match
            }) as i64;
        }

        let fail_stat = calc_stat(fail_results);
        let pass_stat = calc_stat(pass_results);
        macro_rules! calc_summary_ratio {
            ($ratio:ident) => {
                SummaryRatios::from_stats(
                    fail_stat.$ratio,
                    pass_stat.$ratio,
                    ground_truth_positive_count as i64,
                    ground_truth_negative_count as i64,
                )
            };
        }
        SummaryCard {
            at_least_one_file_with_rule_id_match: calc_summary_ratio!(
                at_least_one_file_with_rule_id_match
            ),
            at_least_one_region_with_rule_id_match: calc_summary_ratio!(
                at_least_one_region_with_rule_id_match
            ),
            at_least_one_file_with_cwe_match: calc_summary_ratio!(at_least_one_file_with_cwe_match),
            at_least_one_file_with_cwe_1000_match: calc_summary_ratio!(
                at_least_one_file_with_cwe_1000_match
            ),
            at_least_one_file_without_cwe_match: calc_summary_ratio!(
                at_least_one_file_without_cwe_match
            ),
            at_least_one_region_with_cwe_match: calc_summary_ratio!(
                at_least_one_region_with_cwe_match
            ),
            at_least_one_region_with_cwe_1000_match: calc_summary_ratio!(
                at_least_one_region_with_cwe_1000_match
            ),
            at_least_one_region_without_cwe_match: calc_summary_ratio!(
                at_least_one_region_without_cwe_match
            ),
            ground_truth_negative_count: ground_truth_negative_count as i64,
            ground_truth_positive_count: ground_truth_positive_count as i64,
            truth_positive_cwe_match_count,
            truth_positive_cwe_1000_match_count,
        }
    }

    fn summarize_tool_results(tool_result: &ToolResultsCard) -> SummaryCard {
        let (minimal_matches, matches) = unzip_match_cards(tool_result.result.iter().collect_vec());
        Summarizer::summarize_match_card_vec(minimal_matches, matches)
    }

    fn summarize_tool_results_by_cwe(tool_result: &ToolResultsCard) -> Vec<NamedSummaryCard> {
        fn mk_named_summary_card(cwe: CWEs, results: Vec<&ToolResultCard>) -> NamedSummaryCard {
            let (minimal_matches, matches) = unzip_match_cards(results);
            NamedSummaryCard {
                name: format!("{cwe}"),
                summary: Summarizer::summarize_match_card_vec(minimal_matches, matches),
            }
        }

        tool_result
            .result
            .iter()
            .into_group_map_by(|result| result.expected_result.expected_cwe.clone())
            .into_iter()
            .map(|(cwe, results)| mk_named_summary_card(cwe, results))
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
                    .0
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
                let (minimal_matches, matches) = unzip_match_cards(results);
                NamedSummaryCard {
                    name: format!("{}", CWEs(cwe.clone())),
                    summary: Summarizer::summarize_match_card_vec(minimal_matches, matches),
                }
            })
            .collect()
    }

    fn summarize_recursive(node: &SummaryNode, path: PathBuf) -> ToolsSummaryCard {
        match node {
            SummaryNode::Internal { children } => {
                let mut ret: ToolsSummaryCard = ToolsSummaryCard { summaries: vec![] };
                let mut summary_map: BTreeMap<Tool, Vec<ToolSummaryCard>> = BTreeMap::new();
                for child in children {
                    let summary = Summarizer::summarize_recursive(child.1, path.join(child.0));
                    for summary in summary.summaries {
                        let vec = summary_map.entry(summary.tool.clone()).or_default();
                        vec.push(summary.clone());
                    }
                }
                for (_, summaries) in summary_map {
                    let summary = summaries
                        .into_iter()
                        .reduce(|a_summary, b_summary| a_summary.union(&b_summary))
                        .unwrap();
                    ret.summaries.push(summary);
                }
                let summary_file = File::create(path.join("summary.json")).unwrap();
                serde_json::to_writer_pretty(summary_file, &ret)
                    .expect("error: failure to write summary");
                ret
            }
            SummaryNode::Leaf { summary } => ToolsSummaryCard {
                summaries: vec![*summary.clone()],
            },
        }
    }

    pub fn make_summaries(&mut self, output: PathBuf) {
        for (root, tool) in self
            .runs
            .runs
            .iter()
            .flat_map(|run| run.roots.iter().cartesian_product(run.tools.iter()))
        {
            self.summarize_run(root, tool);
        }

        Self::summarize_recursive(&self.summary_root, output);
    }
}

fn unzip_match_cards(
    results: Vec<&ToolResultCard>,
) -> (Vec<MinimalMatchCard<'_>>, Vec<Vec<MatchCard<'_>>>) {
    let (minimal_matches, matches) = results
        .iter()
        .map(|result| {
            (
                MinimalMatchCard(&result.expected_result, &result.max_minimal_match),
                result.max_match.as_ref().map_or(vec![], |max_match| {
                    max_match
                        .iter()
                        .map(|match_result| MatchCard(&result.expected_result, match_result))
                        .collect()
                }),
            )
        })
        .unzip();
    (minimal_matches, matches)
}

pub fn make_summary(runs: &RunsInfo, output: PathBuf) {
    let results_path = fs::canonicalize(output).unwrap();

    let mut summarizer = Summarizer::new(&runs.runs, results_path.clone());
    summarizer.make_summaries(results_path);
}
