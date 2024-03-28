use std::{
    fs::{self, File},
    path::PathBuf,
};

use super::{description::tools::Tool, metadata::Metadata};

pub struct Directory<'a> {
    pub output: &'a PathBuf,
    pub benchmark: &'a PathBuf,
    pub tool: &'a Tool,
}

impl<'a> Directory<'a> {
    pub fn new(output: &'a PathBuf, benchmark: &'a PathBuf, tool: &'a Tool) -> Self {
        let dir = output.join(benchmark);
        std::fs::create_dir_all(dir).unwrap();
        Directory {
            output,
            benchmark,
            tool,
        }
    }

    pub fn out_file_write(&self) -> File {
        File::create(self.out_path()).unwrap()
    }

    pub fn out_file_read(&self) -> File {
        File::open(self.out_path()).unwrap()
    }

    pub fn err_file_write(&self) -> File {
        File::create(self.err_path()).unwrap()
    }

    pub fn err_file_read(&self) -> File {
        File::open(self.err_path()).unwrap()
    }

    pub fn sarif_file_write(&self) -> File {
        File::create(self.sarif_path()).unwrap()
    }

    pub fn sarif_file_read(&self) -> File {
        File::open(self.sarif_path()).unwrap()
    }

    pub fn evaluate_file_write(&self) -> File {
        File::create(self.evaluate_path()).unwrap()
    }

    pub fn evaluate_file_read(&self) -> File {
        File::open(self.evaluate_path()).unwrap()
    }

    pub fn metadata_write(&self, metadata: &Metadata) {
        serde_json::to_writer_pretty(File::create(self.metadata_path()).unwrap(), &metadata)
            .unwrap()
    }

    pub fn metadata_read(&self) -> Option<Metadata> {
        let file_str = fs::read_to_string(self.metadata_path()).ok()?;
        serde_json::from_str(&file_str).expect("Error: could not parse metadata")
    }

    pub fn out_path(&self) -> PathBuf {
        self.path_to_file("out")
    }

    pub fn err_path(&self) -> PathBuf {
        self.path_to_file("err")
    }

    pub fn metadata_path(&self) -> PathBuf {
        self.path_to_file("metadata")
    }

    pub fn sarif_path(&self) -> PathBuf {
        self.path_to_file("sarif")
    }

    pub fn evaluate_path(&self) -> PathBuf {
        self.path_to_file("json")
    }

    fn tool_name(&self) -> String {
        format!("{}_{}", &self.tool.script, self.tool.config.as_str())
    }

    fn path_to_file(&self, extension: &str) -> PathBuf {
        self.output
            .join(self.benchmark)
            .join(format!("{}.{}", self.tool_name(), extension))
    }
}
