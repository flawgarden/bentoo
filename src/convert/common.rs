use std::collections::{HashMap, HashSet};

use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    RegionBuilder, ReportingDescriptor, ResultBuilder, RunBuilder, Sarif, SarifBuilder,
    ToolBuilder, ToolComponentBuilder,
};

use crate::reference::truth::{CWEs, Rule, CWE};

pub fn collect_tags_rules_map(
    notifications: Option<&Vec<ReportingDescriptor>>,
    tag_prefix: &str,
) -> HashMap<String, HashSet<u64>> {
    let mut rule_to_cwes: HashMap<String, HashSet<u64>> = HashMap::new();
    if let Some(reporting_descriptors) = notifications {
        for reporting_descriptor in reporting_descriptors {
            reporting_descriptor
                .properties
                .as_ref()
                .map(|property_bag| {
                    property_bag.tags.as_ref().map(|tags_vect| {
                        let cwes: HashSet<u64> = tags_vect
                            .iter()
                            .filter_map(|tag| tag.strip_prefix(tag_prefix))
                            .map(|tag| {
                                let cwe: u64 = tag.parse().unwrap();
                                cwe
                            })
                            .collect();
                        if !cwes.is_empty() {
                            rule_to_cwes.insert(reporting_descriptor.id.to_string(), cwes);
                        }
                    })
                });
        }
    };
    rule_to_cwes
}

pub trait RuleMap {
    fn collect_rules_map(
        notifications: Option<&Vec<ReportingDescriptor>>,
    ) -> HashMap<String, HashSet<u64>>;
}

mod tool_sarif_impl {
    use std::collections::{HashMap, HashSet};

    pub trait ToolSarifImpl {
        fn build_results(runs: &[serde_sarif::sarif::Run]) -> Vec<serde_sarif::sarif::Result>;
        fn build_result(
            result: &serde_sarif::sarif::Result,
            rule_to_cwes: &HashMap<String, HashSet<u64>>,
        ) -> Option<serde_sarif::sarif::Result>;
        fn build_locations(
            locations: &[serde_sarif::sarif::Location],
        ) -> Vec<serde_sarif::sarif::Location>;
    }
}
impl<T> tool_sarif_impl::ToolSarifImpl for T
where
    T: RuleMap,
{
    fn build_results(runs: &[serde_sarif::sarif::Run]) -> Vec<serde_sarif::sarif::Result> {
        let mut results_out: Vec<serde_sarif::sarif::Result> = vec![];
        for run in runs {
            let rules = run.tool.driver.rules.as_ref();
            let rule_to_cwes = Self::collect_rules_map(rules);
            let results_opt = run.results.as_ref();
            if let Some(results_in) = results_opt {
                for result in results_in {
                    if let Some(result_out) = Self::build_result(result, &rule_to_cwes) {
                        results_out.push(result_out);
                    }
                }
            }
        }
        results_out
    }

    fn build_result(
        result: &serde_sarif::sarif::Result,
        rule_to_cwes: &HashMap<String, HashSet<u64>>,
    ) -> Option<serde_sarif::sarif::Result> {
        if let Some(rule_id) = result.rule_id.as_ref() {
            if let Some(cwes) = rule_to_cwes.get(rule_id) {
                let cwes = cwes.iter().map(|cwe| CWE(*cwe)).collect();
                let cwes = CWEs(cwes);
                let kind = result.kind.clone();
                result.locations.as_ref().map(|locations| {
                    let mut result_builder = ResultBuilder::default();
                    assert!(rule_to_cwes.contains_key(rule_id));
                    result_builder.rule_id(format!(
                        "{}",
                        Rule {
                            rule_id: rule_id.clone(),
                            cwes,
                        }
                    ));
                    let locations_out = Self::build_locations(locations);
                    result_builder.locations(locations_out);
                    if let Some(kind) = kind {
                        result_builder.kind(kind);
                    }
                    let empty_text = "".to_string();
                    let message = result.message.text.as_ref().unwrap_or(&empty_text);
                    let sarif_message = MessageBuilder::default().text(message).build().unwrap();
                    result_builder.message(sarif_message);
                    result_builder.build().unwrap()
                })
            } else {
                Default::default()
            }
        } else {
            Default::default()
        }
    }

    fn build_locations(
        locations: &[serde_sarif::sarif::Location],
    ) -> Vec<serde_sarif::sarif::Location> {
        let mut locations_out: Vec<serde_sarif::sarif::Location> = vec![];
        for location in locations {
            if let Some(physical_location) = location.physical_location.as_ref() {
                let mut physical_location_builder = PhysicalLocationBuilder::default();
                if let Some(artifact_location) = physical_location.artifact_location.as_ref() {
                    if let Some(uri) = artifact_location.uri.as_ref() {
                        let artifact = ArtifactLocationBuilder::default().uri(uri).build().unwrap();
                        physical_location_builder.artifact_location(artifact);

                        if let Some(region) = physical_location.region.as_ref() {
                            let mut region_builder = RegionBuilder::default();
                            let start_line = region.start_line.unwrap();
                            region_builder.start_line(start_line);
                            if let Some(end_line) = region.end_line {
                                region_builder.end_line(end_line);
                            }
                            if let Some(start_column) = region.start_column {
                                region_builder.start_column(start_column);
                            }
                            if let Some(end_column) = region.end_column {
                                region_builder.end_column(end_column);
                            }
                            physical_location_builder.region(region_builder.build().unwrap());
                        }

                        let physical_location = physical_location_builder.build().unwrap();
                        let location = LocationBuilder::default()
                            .physical_location(physical_location)
                            .build()
                            .unwrap();
                        locations_out.push(location);
                    }
                }
            }
        }
        locations_out
    }
}

pub trait ToolSarif {
    fn build_tool_sarif(self) -> Sarif;
}

pub trait ToolName {
    const TOOL_NAME: &'static str;
}

impl<T> ToolSarif for T
where
    T: tool_sarif_impl::ToolSarifImpl + ToolName,
    Sarif: From<T>,
{
    fn build_tool_sarif(self) -> Sarif {
        let output: Sarif = self.into();
        let runs: &Vec<serde_sarif::sarif::Run> = output.runs.as_ref();
        let results_out = Self::build_results(runs);
        let tool = ToolBuilder::default()
            .driver(
                ToolComponentBuilder::default()
                    .name(Self::TOOL_NAME)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let run = RunBuilder::default()
            .tool(tool)
            .results(results_out)
            .build()
            .unwrap();

        SarifBuilder::default()
            .version("2.1.0")
            .runs(vec![run])
            .build()
            .unwrap()
    }
}
