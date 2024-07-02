use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use crate::{
    reference::{
        taxonomy::{Taxonomy, TaxonomyVersion},
        truth::{CWEs, Kind, ToolResult, ToolResults, TruthResult, TruthResults, CWE},
    },
    util::PartialMax,
};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_sarif::sarif::{self};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ExpectedResult {
    pub expected_kind: Kind,
    pub expected_cwe: CWEs,
}

impl From<&TruthResult> for ExpectedResult {
    fn from(result: &TruthResult) -> Self {
        Self {
            expected_kind: result.kind,
            expected_cwe: result.result.cwes.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct MinimalResultMatch {
    pub cwe_1000_match: bool,
    pub at_least_one_file_match: bool,
    pub cwe_match: bool,
    pub at_least_one_region_match: bool,
    pub reported_cwe: Option<CWEs>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ResultMatch {
    #[serde(flatten)]
    pub minimal_match: MinimalResultMatch,
    pub all_files_match: bool,
    pub all_regions_match: bool,
    pub truth_result: Option<serde_json::Value>,
    pub tool_result: Option<serde_json::Value>,
}

impl ResultMatch {
    fn new(truth_result: serde_json::Value) -> Self {
        Self {
            minimal_match: MinimalResultMatch {
                cwe_1000_match: false,
                at_least_one_file_match: false,
                cwe_match: false,
                at_least_one_region_match: false,
                reported_cwe: None,
            },
            all_files_match: false,
            all_regions_match: false,
            tool_result: None,
            truth_result: Some(truth_result),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct MinimalMatchCard<'a>(pub &'a ExpectedResult, pub &'a MinimalResultMatch);

impl<'a> AsRef<MinimalMatchCard<'a>> for MinimalMatchCard<'a> {
    fn as_ref(&self) -> &MinimalMatchCard<'a> {
        self
    }
}

impl<'a> AsRef<MatchCard<'a>> for MatchCard<'a> {
    fn as_ref(&self) -> &MatchCard<'a> {
        self
    }
}

#[derive(Debug, PartialEq)]
pub struct MatchCard<'a>(pub &'a ExpectedResult, pub &'a ResultMatch);

impl<'a> From<&MatchCard<'a>> for MinimalMatchCard<'a> {
    fn from(tool_card: &MatchCard<'a>) -> Self {
        Self(tool_card.0, &tool_card.1.minimal_match)
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct ToolResultCard {
    pub expected_result: ExpectedResult,
    pub max_match: Vec<ResultMatch>,
    pub max_minimal_match: MinimalResultMatch,
}

impl<'a> PartialOrd for MinimalMatchCard<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.0.expected_kind != other.0.expected_kind {
            return None;
        }
        if self.0.expected_cwe != other.0.expected_cwe {
            return None;
        }
        let self_vector = (
            self.1.cwe_1000_match,
            self.1.at_least_one_file_match,
            self.1.cwe_match,
            self.1.at_least_one_region_match,
        );
        let other_vector = (
            other.1.cwe_1000_match,
            other.1.at_least_one_file_match,
            other.1.cwe_match,
            other.1.at_least_one_region_match,
        );
        match self_vector.cmp(&other_vector) {
            Ordering::Equal => (),
            other => return Some(other),
        }
        if self.1.reported_cwe != other.1.reported_cwe {
            return None;
        }

        Some(Ordering::Equal)
    }
}

impl<'a> PartialOrd for MatchCard<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let self_expected_result = &self.0;
        let other_expected_result = &other.0;
        let self_match = &self.1;
        let other_match = &other.1;
        let self_minimal_match = &self_match.minimal_match;
        let other_minimal_match = &other_match.minimal_match;

        if self_expected_result.expected_kind != other_expected_result.expected_kind {
            return None;
        }
        if self_expected_result.expected_cwe != other_expected_result.expected_cwe {
            return None;
        }

        let cwe_match_ord = (
            self_minimal_match.cwe_1000_match,
            self_minimal_match.cwe_match,
        )
            .cmp(&(
                other_minimal_match.cwe_1000_match,
                other_minimal_match.cwe_match,
            ));
        let files_match_ord = (
            self_minimal_match.at_least_one_file_match,
            self_match.all_files_match,
        )
            .cmp(&(
                other_minimal_match.at_least_one_file_match,
                other_match.all_files_match,
            ));
        let regions_match_ord = (
            self_minimal_match.at_least_one_file_match,
            self_match.all_regions_match,
        )
            .cmp(&(
                other_minimal_match.at_least_one_file_match,
                other_match.all_regions_match,
            ));

        match (cwe_match_ord, files_match_ord, regions_match_ord) {
            (Ordering::Equal, Ordering::Equal, Ordering::Equal) => (),
            (ord, Ordering::Equal, Ordering::Equal)
            | (Ordering::Equal, Ordering::Equal, ord)
            | (Ordering::Equal, ord, Ordering::Equal) => return Some(ord),
            (ord1, ord2, Ordering::Equal)
            | (Ordering::Equal, ord1, ord2)
            | (ord1, Ordering::Equal, ord2)
                if ord1 == ord2 =>
            {
                return Some(ord1)
            }
            (ord1, ord2, ord3) if ord1 == ord2 && ord1 == ord3 => return Some(ord1),
            _ => (),
        }

        if self_minimal_match.reported_cwe != other_minimal_match.reported_cwe {
            return None;
        }

        Some(Ordering::Equal)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolResultsCard {
    pub result: Vec<ToolResultCard>,
}

impl TryFrom<&Path> for ToolResultsCard {
    type Error = serde_json::error::Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let json_str = fs::read_to_string(path).unwrap();
        let result: Self = serde_json::from_str(&json_str)?;
        Ok(result)
    }
}

fn evaluate_tool_result(
    truth_result: &TruthResult,
    tool_result: &ToolResult,
    taxonomy: &Taxonomy,
) -> (ExpectedResult, ResultMatch) {
    let expected_kind = truth_result.kind;
    let expected_cwe = &truth_result.result.cwes;
    let mut at_least_one_file_match = false;
    let mut all_files_match = true;
    let mut at_least_one_region_match = false;
    let mut all_regions_match = true;

    for truth_location in &truth_result.result.locations.0 {
        let mut curr_file_match = false;
        let mut curr_region_match = false;
        for tool_location in &tool_result.result.locations.0 {
            let match_file = truth_location.path == tool_location.path;
            if !match_file {
                continue;
            }
            curr_file_match = true;
            let match_region = match (
                truth_location.region.as_ref(),
                tool_location.region.as_ref(),
            ) {
                (None, None) => true,
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (Some(truth_region), Some(tool_region)) => {
                    match truth_region.partial_cmp(tool_region) {
                        Some(region_ord) => match region_ord {
                            Ordering::Equal | Ordering::Greater => true,
                            Ordering::Less => false,
                        },
                        None => false,
                    }
                }
            };
            if match_region {
                curr_region_match = true;
            }
        }
        all_files_match &= curr_file_match;
        all_regions_match &= curr_region_match;
        at_least_one_file_match |= curr_file_match;
        at_least_one_region_match |= curr_region_match;
    }

    let cwe_match = truth_result
        .result
        .cwes
        .0
        .iter()
        .cartesian_product(tool_result.result.cwes.0.iter())
        .any(
            |(truth_cwe, tool_cwe)| match taxonomy.cwe_partial_cmp(truth_cwe, tool_cwe) {
                Some(ord) => match ord {
                    Ordering::Equal | Ordering::Greater => true,
                    Ordering::Less => false,
                },
                None => false,
            },
        );

    let cwe_1000_match = truth_result
        .result
        .cwes
        .0
        .iter()
        .cartesian_product(tool_result.result.cwes.0.iter())
        .any(|(truth_cwe, tool_cwe)| {
            if let Some(cwe_classes) = taxonomy.to_cwe_1000(truth_cwe) {
                cwe_classes.iter().any(|cwe_class| {
                    match taxonomy.cwe_partial_cmp(cwe_class, tool_cwe) {
                        Some(ord) => match ord {
                            Ordering::Equal | Ordering::Greater => true,
                            Ordering::Less => false,
                        },
                        None => false,
                    }
                })
            } else {
                false
            }
        });

    let expected_cwe = expected_cwe.clone();
    let reported_cwe = Some(tool_result.result.cwes.clone());
    let tool_result_str: String =
        serde_json::to_string_pretty(&sarif::Result::try_from(tool_result).unwrap()).unwrap();
    let truth_result_str: String =
        serde_json::to_string_pretty(&sarif::Result::try_from(truth_result).unwrap()).unwrap();

    (
        ExpectedResult {
            expected_kind,
            expected_cwe,
        },
        ResultMatch {
            minimal_match: MinimalResultMatch {
                cwe_1000_match,
                at_least_one_file_match,
                cwe_match,
                at_least_one_region_match,
                reported_cwe,
            },
            all_files_match,
            all_regions_match,
            tool_result: Some(serde_json::from_str(tool_result_str.as_str()).unwrap()),
            truth_result: Some(serde_json::from_str(truth_result_str.as_str()).unwrap()),
        },
    )
}

fn evaluate_tool_results(
    truth_result: &TruthResult,
    path_to_tool_results: &HashMap<&String, HashSet<&ToolResult>>,
    cwe_to_tool_results: &HashMap<&CWE, HashSet<&ToolResult>>,
    taxonomy: &Taxonomy,
) -> ToolResultCard {
    let mut tool_results_to_evaluate: HashSet<&ToolResult> = HashSet::new();
    for truth_location in &truth_result.result.locations.0 {
        if let Some(tool_results) = path_to_tool_results.get(&truth_location.path) {
            for tool_result in tool_results {
                tool_results_to_evaluate.insert(tool_result);
            }
        }
    }
    for truth_cwe in &truth_result.result.cwes.0 {
        if let Some(tool_results) = cwe_to_tool_results.get(truth_cwe) {
            for tool_result in tool_results {
                tool_results_to_evaluate.insert(tool_result);
            }
        }
    }
    let max_result_cards = tool_results_to_evaluate
        .iter()
        .map(|tool_result| evaluate_tool_result(truth_result, tool_result, taxonomy))
        .partial_max_by(
            |(result_left, result_match_left), (result_right, result_match_right)| {
                MatchCard(result_left, result_match_left)
                    .partial_cmp(&MatchCard(result_right, result_match_right))
            },
        )
        .into_iter()
        .map(|tool_result| tool_result.1)
        .collect_vec();
    let truth_result_str: String =
        serde_json::to_string_pretty(&sarif::Result::try_from(truth_result).unwrap()).unwrap();
    let tool_result_card = tool_results_to_evaluate
        .iter()
        .map(|tool_result| evaluate_tool_result(truth_result, tool_result, taxonomy))
        .reduce(|acc, card| {
            match MinimalMatchCard(&acc.0, &acc.1.minimal_match)
                .partial_cmp(&MinimalMatchCard(&card.0, &card.1.minimal_match))
            {
                Some(ord) => match ord {
                    Ordering::Less => card,
                    Ordering::Equal | Ordering::Greater => acc,
                },
                None => acc,
            }
        })
        .unwrap_or((
            ExpectedResult {
                expected_kind: truth_result.kind,
                expected_cwe: truth_result.result.cwes.clone(),
            },
            ResultMatch::new(serde_json::from_str(truth_result_str.as_str()).unwrap()),
        ));
    ToolResultCard {
        max_match: max_result_cards,
        expected_result: ExpectedResult::from(truth_result),
        max_minimal_match: tool_result_card.1.minimal_match,
    }
}

pub fn evaluate_tool(
    truth_results: &TruthResults,
    tool_results: &ToolResults,
    taxonomy: Option<&Taxonomy>,
) -> ToolResultsCard {
    fn inner_evaluate_tool(
        truth_results: &TruthResults,
        tool_results: &ToolResults,
        taxonomy: &Taxonomy,
    ) -> ToolResultsCard {
        let path_to_tool_results = prepare_path_to_tool_results(tool_results);
        let mut cwe_to_tool_results: HashMap<&CWE, HashSet<&ToolResult>> = HashMap::new();
        for result in &tool_results.results {
            for tool_cwe in &result.result.cwes.0 {
                let entry = cwe_to_tool_results.entry(tool_cwe).or_default();
                entry.insert(result);
            }
        }

        let result = truth_results
            .results
            .iter()
            .map(|truth_result| {
                evaluate_tool_results(
                    truth_result,
                    &path_to_tool_results,
                    &cwe_to_tool_results,
                    taxonomy,
                )
            })
            .collect();
        ToolResultsCard { result }
    }
    if let Some(taxonomy) = taxonomy {
        inner_evaluate_tool(truth_results, tool_results, taxonomy)
    } else {
        let taxonomy = prepare_taxonomy();
        inner_evaluate_tool(truth_results, tool_results, &taxonomy)
    }
}

fn prepare_taxonomy() -> Taxonomy {
    Taxonomy::from_known_version(&TaxonomyVersion::default())
}

fn prepare_path_to_tool_results(
    tool_results: &ToolResults,
) -> HashMap<&String, HashSet<&ToolResult>> {
    let mut path_to_tool_results: HashMap<&String, HashSet<&ToolResult>> = HashMap::new();
    for result in &tool_results.results {
        for location in &result.result.locations.0 {
            let entry = path_to_tool_results.entry(&location.path).or_default();
            entry.insert(result);
        }
    }
    path_to_tool_results
}
