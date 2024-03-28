use std::io::BufReader;
use std::time::Duration;
use std::{fs::File, io::Read};

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum Status {
    #[default]
    Exited,
    ScriptError,
    Timeout,
}

#[derive(PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum ParseStatus {
    #[default]
    No,
    Failed,
    Yes,
}

#[derive(Deserialize, Serialize, Default)]
pub struct Metadata {
    pub status: Status,
    pub exit_code: i32,
    pub time: Duration,
    pub parsed: ParseStatus,
    pub evaluated: bool,
}

impl Metadata {
    pub fn from_file(path: &File) -> Self {
        let mut file_str = String::default();
        let mut buf_reader = BufReader::new(path);
        buf_reader.read_to_string(&mut file_str).unwrap();
        serde_json::from_str(&file_str).unwrap()
    }

    pub fn to_file(&self, file: &File) {
        serde_json::to_writer_pretty(file, self).unwrap();
    }
}
