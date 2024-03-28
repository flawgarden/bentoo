use std::collections::{HashMap, HashSet};

use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    RegionBuilder, ReportingDescriptor, ResultBuilder, RunBuilder, Sarif, SarifBuilder,
    ToolBuilder, ToolComponentBuilder,
};

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
        ) -> Vec<serde_sarif::sarif::Result>;
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
                    let mut result_out = Self::build_result(result, &rule_to_cwes);
                    results_out.append(&mut result_out);
                }
            }
        }
        results_out
    }

    fn build_result(
        result: &serde_sarif::sarif::Result,
        rule_to_cwes: &HashMap<String, HashSet<u64>>,
    ) -> Vec<serde_sarif::sarif::Result> {
        if let Some(rule_id) = result.rule_id.as_ref() {
            rule_to_cwes[rule_id]
                .iter()
                .filter_map(|cwe| {
                    result.locations.as_ref().map(|locations| {
                        let mut result_builder = ResultBuilder::default();
                        assert!(rule_to_cwes.contains_key(rule_id));
                        result_builder.rule_id("CWE-".to_string() + cwe.to_string().as_str());
                        let locations_out = Self::build_locations(locations);
                        result_builder.locations(locations_out);
                        let empty_text = "".to_string();
                        let message = result.message.text.as_ref().unwrap_or(&empty_text);
                        let sarif_message =
                            MessageBuilder::default().text(message).build().unwrap();
                        result_builder.message(sarif_message);
                        result_builder.build().unwrap()
                    })
                })
                .collect()
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
                let uri = physical_location
                    .artifact_location
                    .as_ref()
                    .unwrap()
                    .uri
                    .as_ref()
                    .unwrap();
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
