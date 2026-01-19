use std::{fs, path::Path};

use serde_sarif::sarif::{
    ArtifactLocationBuilder, LocationBuilder, MessageBuilder, PhysicalLocationBuilder,
    RegionBuilder, ResultBuilder, RunBuilder, Sarif, SarifBuilder, ToolBuilder,
    ToolComponentBuilder,
};

/// Extracts CWE number from Qodana message text by looking for known sink types.
/// Pattern: "... passed to {sink_type} sink"
fn extract_cwe_from_message(message: &str) -> Option<u64> {
    const SINK_PREFIX: &str = "passed to ";
    const SINK_SUFFIX: &str = " sink";

    // Known sink type to CWE mappings
    let sink_mappings: &[(&str, u64)] = &[
        ("Command injection", 78),
        ("Cross-Site Scripting (XSS)", 79),
        ("SQL injection", 89),
        ("Path Traversal", 22),
        ("LDAP injection", 90),
        ("Response Splitting", 113),
        ("XPath injection", 643),
    ];

    // Find "passed to " in the message
    let start_idx = message.find(SINK_PREFIX)?;
    let after_prefix = &message[start_idx + SINK_PREFIX.len()..];

    // Find " sink" after the prefix
    let end_idx = after_prefix.find(SINK_SUFFIX)?;
    let sink_type = &after_prefix[..end_idx];

    // Look up CWE for this sink type
    sink_mappings
        .iter()
        .find(|(name, _)| *name == sink_type)
        .map(|(_, cwe)| *cwe)
}

fn from_report(sarif: &Sarif) -> Sarif {
    let mut results = vec![];

    for run in &sarif.runs {
        if let Some(run_results) = run.results.as_ref() {
            for result in run_results {
                let message_text = result
                    .message
                    .text
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("");

                // Extract CWE from message text
                let cwe = extract_cwe_from_message(message_text);

                // Skip results without a recognized CWE mapping
                let cwe = match cwe {
                    Some(cwe) => cwe,
                    None => continue,
                };

                // Get the original rule_id for the combined rule format
                let original_rule_id = result
                    .rule_id
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("JvmTaintAnalysis");

                let mut result_builder = ResultBuilder::default();

                // Set rule_id in format "CWE-XX:OriginalRuleId"
                result_builder.rule_id(format!("CWE-{}:{}", cwe, original_rule_id));

                // Build locations
                if let Some(locations) = result.locations.as_ref() {
                    let mut locations_out = vec![];
                    for location in locations {
                        if let Some(physical_location) = location.physical_location.as_ref() {
                            let mut physical_location_builder = PhysicalLocationBuilder::default();

                            if let Some(artifact_location) =
                                physical_location.artifact_location.as_ref()
                            {
                                if let Some(uri) = artifact_location.uri.as_ref() {
                                    let artifact = ArtifactLocationBuilder::default()
                                        .uri(uri)
                                        .build()
                                        .unwrap();
                                    physical_location_builder.artifact_location(artifact);

                                    if let Some(region) = physical_location.region.as_ref() {
                                        let mut region_builder = RegionBuilder::default();
                                        if let Some(start_line) = region.start_line {
                                            region_builder.start_line(start_line);
                                        }
                                        if let Some(end_line) = region.end_line {
                                            region_builder.end_line(end_line);
                                        }
                                        if let Some(start_column) = region.start_column {
                                            region_builder.start_column(start_column);
                                        }
                                        if let Some(end_column) = region.end_column {
                                            region_builder.end_column(end_column);
                                        }
                                        physical_location_builder
                                            .region(region_builder.build().unwrap());
                                    }

                                    let physical_location =
                                        physical_location_builder.build().unwrap();
                                    let location = LocationBuilder::default()
                                        .physical_location(physical_location)
                                        .build()
                                        .unwrap();
                                    locations_out.push(location);
                                }
                            }
                        }
                    }
                    result_builder.locations(locations_out);
                }

                // Preserve the original message
                let sarif_message = MessageBuilder::default()
                    .text(message_text)
                    .build()
                    .unwrap();
                result_builder.message(sarif_message);

                results.push(result_builder.build().unwrap());
            }
        }
    }

    let tool = ToolBuilder::default()
        .driver(
            ToolComponentBuilder::default()
                .name("qodana")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let run = RunBuilder::default()
        .tool(tool)
        .results(results)
        .build()
        .unwrap();

    SarifBuilder::default()
        .version("2.1.0")
        .runs(vec![run])
        .build()
        .unwrap()
}

pub fn from_file(path: &Path) -> Sarif {
    let json_str = fs::read_to_string(path).unwrap();
    from_string(&json_str)
}

pub fn from_string(string: &str) -> Sarif {
    let sarif: Sarif = serde_json::from_str(string).unwrap();
    from_report(&sarif)
}
