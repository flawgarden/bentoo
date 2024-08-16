use core::fmt;
use std::{
    cmp::Ordering,
    convert::From,
    fs,
    hash::Hash,
    io::{BufReader, Read},
    path::Path,
    result,
};

use serde::{Deserialize, Serialize};
use serde_sarif::{
    self,
    sarif::{
        self, ArtifactLocationBuilder, LocationBuilder, MessageBuilder, ResultBuilder, RunBuilder,
        Sarif, SarifBuilder, ToolBuilder, ToolComponentBuilder,
    },
};

use thiserror::Error;

#[derive(Error, Debug)]
pub struct ParseError {
    pub message: String,
}

impl ParseError {
    fn new<S: AsRef<str>>(message: S) -> Self {
        let message = message.as_ref().to_string();
        Self { message }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Truth/Tool Parse error: {}", self.message)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Deserialize, Serialize)]
pub enum Kind {
    Pass,
    Fail,
}

#[derive(PartialEq, Eq, Hash)]
pub struct Region {
    start_line: i64,
    end_line: Option<i64>,
    start_column: Option<i64>,
    end_column: Option<i64>,
}

impl PartialOrd for Region {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let start_line_ord = self.start_line.cmp(&other.start_line);
        let self_end_line = self.end_line.unwrap_or(self.start_line);
        let other_end_line = other.end_line.unwrap_or(other.start_line);
        let end_line_ord = self_end_line.cmp(&other_end_line);
        let line_ord = match (start_line_ord, end_line_ord) {
            (Ordering::Equal, Ordering::Less) => Some(Ordering::Less),
            (Ordering::Greater, Ordering::Equal) => Some(Ordering::Less),
            (Ordering::Greater, Ordering::Less) => Some(Ordering::Less),
            (Ordering::Equal, Ordering::Equal) => Some(Ordering::Equal),
            (Ordering::Less, Ordering::Equal) => Some(Ordering::Greater),
            (Ordering::Equal, Ordering::Greater) => Some(Ordering::Greater),
            (Ordering::Less, Ordering::Greater) => Some(Ordering::Greater),
            (Ordering::Less, Ordering::Less) => None,
            (Ordering::Greater, Ordering::Greater) => None,
        };
        line_ord?;
        let line_ord = line_ord.unwrap();
        let start_column_ord = match (self.start_column, other.start_column) {
            (None, None) => Ordering::Equal,
            (None, Some(1)) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(1), None) => Ordering::Equal,
            (Some(_), None) => Ordering::Greater,
            (Some(self_start_column), Some(other_start_column)) => {
                self_start_column.cmp(&other_start_column)
            }
        };
        let end_column_ord = match (self.end_column, other.end_column) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(self_end_column), Some(other_end_column)) => {
                self_end_column.cmp(&other_end_column)
            }
        };
        match (line_ord, start_line_ord, end_line_ord) {
            (Ordering::Less, Ordering::Equal, _) => match start_column_ord {
                Ordering::Equal => Some(Ordering::Less),
                Ordering::Greater => Some(Ordering::Less),
                Ordering::Less => None,
            },
            (Ordering::Less, _, Ordering::Equal) => match end_column_ord {
                Ordering::Equal => Some(Ordering::Less),
                Ordering::Less => Some(Ordering::Less),
                Ordering::Greater => None,
            },
            (Ordering::Greater, Ordering::Equal, _) => match start_column_ord {
                Ordering::Less => Some(Ordering::Greater),
                Ordering::Equal => Some(Ordering::Greater),
                Ordering::Greater => None,
            },
            (Ordering::Greater, _, Ordering::Equal) => match end_column_ord {
                Ordering::Equal => Some(Ordering::Greater),
                Ordering::Greater => Some(Ordering::Greater),
                Ordering::Less => None,
            },
            (Ordering::Equal, _, _) => match (start_column_ord, end_column_ord) {
                (Ordering::Equal, Ordering::Less) => Some(Ordering::Less),
                (Ordering::Greater, Ordering::Equal) => Some(Ordering::Less),
                (Ordering::Greater, Ordering::Less) => Some(Ordering::Less),
                (Ordering::Equal, Ordering::Equal) => Some(Ordering::Equal),
                (Ordering::Less, Ordering::Equal) => Some(Ordering::Greater),
                (Ordering::Equal, Ordering::Greater) => Some(Ordering::Greater),
                (Ordering::Less, Ordering::Greater) => Some(Ordering::Greater),
                (Ordering::Less, Ordering::Less) => None,
                (Ordering::Greater, Ordering::Greater) => None,
            },
            _ => Some(line_ord),
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub enum RelationshipKind {
    Flows,
    IsSourcedFrom,
}

#[derive(PartialEq, Eq, Hash)]
pub struct LocationRelationship {
    pub target: u64,
    pub kinds: Vec<RelationshipKind>,
}

#[derive(PartialEq, Eq, Hash)]
pub struct Location {
    pub id: i64,
    pub path: String,
    pub region: Option<Region>,
    pub relationship: Option<()>,
}

#[derive(PartialEq, Eq, Hash)]
pub struct Locations(pub Vec<Location>);

#[derive(Serialize, Deserialize, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Clone, Copy)]
pub struct CWE(pub u64);

impl fmt::Display for CWE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CWE-{}", self.0)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Clone)]
pub struct CWEs(pub Vec<CWE>);

impl fmt::Display for CWEs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.0.is_empty() {
            write!(f, "{}", self.0.first().unwrap())?
        }
        if self.0.len() > 1 {
            for cwe in &self.0[1..self.0.len()] {
                write!(f, ",{}", cwe)?;
            }
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Result {
    pub cwes: CWEs,
    pub message: Option<String>,
    pub locations: Locations,
    pub related_locations: Option<Locations>,
}

#[derive(PartialEq, Eq, Hash)]
pub struct TruthResult {
    pub kind: Kind,
    pub result: Result,
}

#[derive(PartialEq, Eq, Hash)]
pub struct ToolResult {
    pub result: Result,
}

#[derive(PartialEq, Eq, Hash)]
pub struct TruthResults {
    pub name: String,
    pub results: Vec<TruthResult>,
}

#[derive(PartialEq, Eq, Hash)]
pub struct ToolResults {
    pub name: String,
    pub results: Vec<ToolResult>,
}

fn resolve_kind(result: &sarif::Result) -> result::Result<sarif::ResultKind, ParseError> {
    let kind_str = result
        .kind
        .as_ref()
        .map_or(Some("fail"), |k| k.as_str())
        .unwrap();
    match kind_str {
        "fail" => Ok(sarif::ResultKind::Fail),
        "notApplicable" => Ok(sarif::ResultKind::NotApplicable),
        "pass" => Ok(sarif::ResultKind::Pass),
        "review" => Ok(sarif::ResultKind::Review),
        "open" => Ok(sarif::ResultKind::Open),
        "informational" => Ok(sarif::ResultKind::Informational),
        _ => Err(ParseError::new(format!("Unexpected kind: {}", kind_str))),
    }
}

impl TryFrom<&sarif::ResultKind> for Kind {
    type Error = ParseError;
    fn try_from(kind: &sarif::ResultKind) -> result::Result<Self, ParseError> {
        match kind {
            sarif::ResultKind::Pass => Ok(Kind::Pass),
            sarif::ResultKind::Fail => Ok(Kind::Fail),
            _ => Err(ParseError::new(format!("Unexpected kind: {}", kind))),
        }
    }
}

impl From<&Kind> for sarif::ResultKind {
    fn from(kind: &Kind) -> Self {
        match kind {
            Kind::Pass => sarif::ResultKind::Pass,
            Kind::Fail => sarif::ResultKind::Fail,
        }
    }
}

impl TryFrom<&sarif::Region> for Region {
    type Error = ParseError;
    fn try_from(region: &sarif::Region) -> result::Result<Self, ParseError> {
        if let Some(start_line) = region.start_line {
            Ok(Self {
                start_line,
                end_line: region.end_line,
                start_column: region.end_column,
                end_column: region.end_column,
            })
        } else {
            Err(ParseError::new("Region should have a start line"))
        }
    }
}

impl TryFrom<&Region> for sarif::Region {
    type Error = ParseError;
    fn try_from(region: &Region) -> result::Result<Self, ParseError> {
        let mut builder = sarif::RegionBuilder::default();
        builder.start_line(region.start_line);
        if let Some(end_line) = region.end_line {
            builder.end_line(end_line);
        }
        if let Some(start_column) = region.start_column {
            builder.start_column(start_column);
        }
        if let Some(end_column) = region.end_column {
            builder.end_column(end_column);
        }
        builder
            .build()
            .map_err(|_| ParseError::new("Region build failed"))
    }
}

impl TryFrom<&sarif::PhysicalLocation> for Location {
    type Error = ParseError;
    fn try_from(location: &sarif::PhysicalLocation) -> result::Result<Self, ParseError> {
        let path = location
            .artifact_location
            .as_ref()
            .ok_or(ParseError::new("Location should have an artifact location"))?
            .uri
            .as_ref()
            .ok_or(ParseError::new("Artifact should have an uri"))?
            .clone();
        let region = location.region.as_ref();
        let region = match region {
            None => None,
            Some(region) => Some(Region::try_from(region)?),
        };
        Ok(Self {
            path,
            region,
            id: 0,
            relationship: None,
        })
    }
}

impl TryFrom<&Location> for sarif::PhysicalLocation {
    type Error = ParseError;
    fn try_from(location: &Location) -> result::Result<Self, ParseError> {
        let uri = location.path.clone();
        let artifact = ArtifactLocationBuilder::default().uri(uri).build().unwrap();
        let region = location.region.as_ref();
        let region = match region {
            None => None,
            Some(region) => Some(sarif::Region::try_from(region)?),
        };
        let mut builder = sarif::PhysicalLocationBuilder::default();
        builder.artifact_location(artifact);
        if let Some(region) = region {
            builder.region(region);
        }
        builder
            .build()
            .map_err(|_| ParseError::new("Location build failed"))
    }
}

impl TryFrom<&Vec<sarif::Location>> for Locations {
    type Error = ParseError;

    fn try_from(locations: &Vec<sarif::Location>) -> result::Result<Self, ParseError> {
        let mut parsed = vec![];
        for location in locations {
            let physical_location = location
                .physical_location
                .as_ref()
                .ok_or(ParseError::new("Location should have a physical location"))?;
            let id = location
                .id
                .ok_or(ParseError::new("Location should have an id"))?;
            let location = Location::try_from(physical_location)?;
            parsed.push(Location { id, ..location });
        }
        Ok(Self(parsed))
    }
}

impl TryFrom<&Locations> for Vec<sarif::Location> {
    type Error = ParseError;

    fn try_from(locations: &Locations) -> result::Result<Self, ParseError> {
        let mut parsed = vec![];
        for location in &locations.0 {
            let physical_location = sarif::PhysicalLocation::try_from(location)?;
            let loc = LocationBuilder::default()
                .physical_location(physical_location)
                .build()
                .map_err(|_| ParseError::new("Location build failed"))?;
            parsed.push(loc);
        }
        Ok(parsed)
    }
}

impl TryFrom<&sarif::Result> for Result {
    type Error = ParseError;

    fn try_from(result: &sarif::Result) -> result::Result<Self, ParseError> {
        let cwes: Vec<CWE> = result
            .rule_id
            .as_ref()
            .ok_or(ParseError::new("Result should have a rule id"))?
            .split(',')
            .map(|cwe| {
                let cwe = cwe
                    .trim()
                    .strip_prefix("CWE-")
                    .ok_or(ParseError::new(
                        "Every part of rule id should start with 'CWE-'",
                    ))?
                    .parse()
                    .map_err(|_| ParseError::new("CWE parsing failed"))?;
                result::Result::<CWE, ParseError>::Ok(CWE(cwe))
            })
            .collect::<result::Result<Vec<CWE>, ParseError>>()?;
        let cwes = CWEs(cwes);
        let message = result.message.text.clone();
        let locations = result.locations.as_ref();
        let locations = match locations {
            None => Locations(vec![]),
            Some(locations) => Locations::try_from(locations)?,
        };
        Ok(Self {
            locations,
            message,
            cwes,
            related_locations: None,
        })
    }
}

impl TryFrom<&Result> for sarif::Result {
    type Error = ParseError;

    fn try_from(result: &Result) -> result::Result<Self, ParseError> {
        let mut result_builder = ResultBuilder::default();
        let cwes = format!("{}", result.cwes);
        let locations = Vec::try_from(&result.locations)?;
        result_builder.rule_id(cwes).locations(locations);
        if let Some(text) = result.message.as_ref() {
            let message = MessageBuilder::default()
                .text(text)
                .build()
                .map_err(|_| ParseError::new("Message build failed"))?;
            result_builder.message(message);
        }
        result_builder
            .build()
            .map_err(|_| ParseError::new("Result build failed"))
    }
}

impl TryFrom<&sarif::Result> for TruthResult {
    type Error = ParseError;

    fn try_from(result: &sarif::Result) -> result::Result<Self, ParseError> {
        let kind = resolve_kind(result)?;
        let kind: Kind = Kind::try_from(&kind)?;
        let result = Result::try_from(result)?;
        Ok(Self { kind, result })
    }
}

impl TryFrom<&sarif::Result> for ToolResult {
    type Error = ParseError;

    fn try_from(result: &sarif::Result) -> result::Result<Self, ParseError> {
        let result = Result::try_from(result)?;
        Ok(Self { result })
    }
}

impl TryFrom<&ToolResult> for sarif::Result {
    type Error = ParseError;
    fn try_from(result: &ToolResult) -> result::Result<Self, ParseError> {
        sarif::Result::try_from(&result.result)
    }
}

impl TryFrom<&TruthResult> for sarif::Result {
    type Error = ParseError;
    fn try_from(result: &TruthResult) -> result::Result<Self, ParseError> {
        sarif::Result::try_from(&result.result)
    }
}

impl TryFrom<&sarif::Sarif> for TruthResults {
    type Error = ParseError;

    fn try_from(sarif: &sarif::Sarif) -> result::Result<Self, ParseError> {
        assert_eq!(sarif.runs.len(), 1);
        let run = sarif.runs.first().unwrap();
        let mut results = vec![];
        for result in run
            .results
            .as_ref()
            .ok_or(ParseError::new("Run should have results"))?
        {
            results.push(TruthResult::try_from(result)?);
        }
        let name = run.tool.driver.name.clone();
        Ok(Self { name, results })
    }
}

impl TryFrom<&sarif::Sarif> for ToolResults {
    type Error = ParseError;
    fn try_from(sarif: &sarif::Sarif) -> result::Result<Self, ParseError> {
        assert_eq!(sarif.runs.len(), 1);
        let run = sarif.runs.first().unwrap();
        let mut results = vec![];
        for result in run
            .results
            .as_ref()
            .ok_or(ParseError::new("Run should have results"))?
        {
            results.push(ToolResult::try_from(result)?)
        }
        let name = run.tool.driver.name.clone();
        Ok(Self { name, results })
    }
}

impl TryFrom<&ToolResults> for sarif::Sarif {
    type Error = ParseError;
    fn try_from(sarif: &ToolResults) -> result::Result<Self, ParseError> {
        let name = sarif.name.clone();
        let mut results = vec![];
        for result in &sarif.results {
            results.push(sarif::Result::try_from(result)?);
        }

        let tool_component = ToolComponentBuilder::default()
            .name(name)
            .build()
            .map_err(|_| ParseError::new("Tool component build failed"))?;
        let tool = ToolBuilder::default()
            .driver(tool_component)
            .build()
            .map_err(|_| ParseError::new("Tool build failed"))?;
        let run = RunBuilder::default()
            .tool(tool)
            .results(results)
            .build()
            .map_err(|_| ParseError::new("Run build failed"))?;

        SarifBuilder::default()
            .version("2.1.0")
            .runs(vec![run])
            .build()
            .map_err(|_| ParseError::new("Sarif build failed"))
    }
}

impl TryFrom<&Path> for TruthResults {
    type Error = ParseError;

    fn try_from(path: &Path) -> result::Result<Self, ParseError> {
        if let Ok(file) = fs::File::open(path) {
            let mut file_str = String::default();
            let mut buf_reader = BufReader::new(file);
            buf_reader
                .read_to_string(&mut file_str)
                .map_err(|_| ParseError::new("Read from buffer to string failed"))?;
            let report: Option<Sarif> = serde_json::from_str(&file_str).ok();
            if let Some(report) = report {
                return TruthResults::try_from(&report);
            }
        }
        Ok(TruthResults {
            name: path.to_path_buf().into_os_string().into_string().unwrap(),
            results: vec![],
        })
    }
}

impl TryFrom<&Path> for ToolResults {
    type Error = ParseError;

    fn try_from(path: &Path) -> result::Result<Self, ParseError> {
        if let Ok(file) = fs::File::open(path) {
            let mut file_str = String::default();
            let mut buf_reader = BufReader::new(file);
            buf_reader
                .read_to_string(&mut file_str)
                .map_err(|_| ParseError::new("Read from buffer to string failed"))?;
            let report: Option<Sarif> = serde_json::from_str(&file_str).ok();
            if let Some(report) = report {
                return ToolResults::try_from(&report);
            }
        }
        Ok(ToolResults {
            name: path.to_path_buf().into_os_string().into_string().unwrap(),
            results: vec![],
        })
    }
}
