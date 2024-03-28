use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use serde_sarif::sarif::Sarif;

use super::truth::CWE;

const SUPPORTED_VERSIONS: &[&str] = &["4.14"];

pub struct TaxonomyVersion(pub String);

impl Default for TaxonomyVersion {
    fn default() -> Self {
        Self(SUPPORTED_VERSIONS.first().unwrap().to_string())
    }
}

pub struct Taxonomy {
    pub version: TaxonomyVersion,
    pub parents: HashMap<CWE, HashSet<CWE>>,
    pub cwe_1000: HashSet<CWE>,
    pub cwe_to_cwe_classes: HashMap<CWE, HashSet<CWE>>,
}

impl Taxonomy {
    pub fn from_sarif(sarif: &Sarif) -> Self {
        let mut parent: HashMap<CWE, HashSet<CWE>> = HashMap::default();
        let mut cwe_1000: HashSet<CWE> = HashSet::default();
        let taxonomy = &sarif.runs[0];
        let taxonomy = &taxonomy.taxonomies.as_ref().unwrap()[0];

        for cwe in taxonomy.taxa.as_ref().unwrap() {
            let number: u64 = cwe.id[4..].parse().unwrap(); // "CWE-n" to n
            if let Some(relationships) = &cwe.relationships {
                for relationship in relationships {
                    let kinds = relationship.kinds.as_ref().unwrap();
                    assert!(kinds.len() == 1);
                    if kinds[0] == "superset" {
                        let parent_number: u64 = relationship.target.id.as_ref().unwrap()[4..]
                            .parse()
                            .unwrap();
                        let entry = parent.entry(CWE { cwe: number }).or_default();
                        entry.insert(CWE { cwe: parent_number });
                    }
                    if number == 1000 && kinds[0] == "subset" {
                        let class_number: u64 = relationship.target.id.as_ref().unwrap()[4..]
                            .parse()
                            .unwrap();
                        cwe_1000.insert(CWE { cwe: class_number });
                    }
                }
            }
        }
        let taxanomy = Taxonomy {
            version: TaxonomyVersion(taxonomy.version.clone().unwrap()),
            parents: parent,
            cwe_1000,
            cwe_to_cwe_classes: Default::default(),
        };
        let mut cwe_to_cwe_classes = HashMap::default();
        for cwe in taxanomy.parents.keys() {
            let mut cwe_1000_classes: HashSet<CWE> = HashSet::default();
            for cwe_class in taxanomy.cwe_1000.iter() {
                if let Some(Ordering::Greater) | Some(Ordering::Equal) =
                    taxanomy.cwe_partial_cmp(cwe_class, cwe)
                {
                    cwe_1000_classes.insert(*cwe_class);
                }
            }
            cwe_to_cwe_classes.insert(*cwe, cwe_1000_classes);
        }

        Taxonomy {
            cwe_to_cwe_classes,
            ..taxanomy
        }
    }

    pub fn from_file(path: &Path) -> Self {
        let file_str = fs::read_to_string(path).unwrap();
        Self::from_string(&file_str)
    }

    pub fn from_string(string: &str) -> Self {
        let sarif: Sarif = serde_json::from_str(string).unwrap();
        Self::from_sarif(&sarif)
    }

    pub fn from_known_version(version: &TaxonomyVersion) -> Self {
        let taxonomy: &str = match version.0.as_str() {
            "4.14" => {
                include_str!("../../taxonomies/CWE_v4.14.sarif")
            }
            _ => {
                panic!(
                    "Unknown CWE Taxonomy version! Supported versions are {:?}",
                    SUPPORTED_VERSIONS
                );
            }
        };
        Self::from_string(taxonomy)
    }

    pub fn cwe_partial_cmp(&self, left: &CWE, right: &CWE) -> Option<Ordering> {
        if left == right {
            return Some(Ordering::Equal);
        }

        let mut stack: Vec<&CWE> = vec![left];
        while let Some(left_cwe) = stack.pop() {
            if left_cwe == right {
                return Some(Ordering::Less);
            }

            if let Some(parents) = self.parents.get(left_cwe) {
                for parent in parents {
                    stack.push(parent);
                }
            }
        }
        stack.push(right);

        while let Some(right_cwe) = stack.pop() {
            if right_cwe == left {
                return Some(Ordering::Greater);
            }

            if let Some(parents) = self.parents.get(right_cwe) {
                for parent in parents {
                    stack.push(parent);
                }
            }
        }
        None
    }

    pub fn to_cwe_1000(&self, cwe: &CWE) -> Option<&HashSet<CWE>> {
        self.cwe_to_cwe_classes.get(cwe)
    }
}
