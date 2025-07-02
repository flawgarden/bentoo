use std::{
    cmp::Ordering,
    fs, io,
    path::{Path, PathBuf},
    process::{Child, ExitStatus},
    thread::sleep,
    time::{Duration, Instant},
};

use walkdir::WalkDir;

pub fn copy_dir(src: &Path, dst: &Path) -> Result<(), io::Error> {
    for entry in WalkDir::new(src)
        .into_iter()
        .filter_entry(|e| e.file_name() != dst.file_name().unwrap())
    {
        let entry = entry?;

        let from = entry.path();
        let to = dst.join(from.strip_prefix(src).unwrap());

        // create directories
        if entry.file_type().is_dir() {
            if let Err(e) = fs::create_dir(to) {
                match e.kind() {
                    io::ErrorKind::AlreadyExists => {}
                    _ => return Err(e),
                }
            }
        }
        // copy files
        else if entry.file_type().is_file() {
            fs::copy(from, to)?;
        }
    }
    Ok(())
}

fn find_files_generic<P: Fn(&Path) -> bool>(
    root_path: &Path,
    file_name_predicate: &P,
    recursive: bool,
) -> Vec<PathBuf> {
    let mut paths = vec![];
    let mut walker = WalkDir::new(root_path);
    if !recursive {
        walker = walker.max_depth(0);
    }
    for entry in walker.into_iter().filter_entry(|entry| {
        entry.metadata().is_ok_and(|metadata| metadata.is_dir())
            || file_name_predicate(entry.path())
    }) {
        let entry = entry.unwrap();
        let metadata = entry.metadata().unwrap();
        if metadata.is_file() {
            paths.push(entry.path().strip_prefix(root_path).unwrap().to_path_buf())
        }
    }

    paths
}

pub fn find_files_recursive<P: Fn(&Path) -> bool>(
    root_path: &Path,
    file_name_predicate: &P,
) -> Vec<PathBuf> {
    find_files_generic(root_path, file_name_predicate, true)
}

pub fn find_files<P: Fn(&Path) -> bool>(root_path: &Path, file_name_predicate: &P) -> Vec<PathBuf> {
    find_files_generic(root_path, file_name_predicate, false)
}

pub fn round_dp3(number: f64) -> f64 {
    format!("{number:.3}",).parse().unwrap()
}

pub trait PartialMax: Iterator {
    fn partial_max_by<F>(self, partial_cmp: F) -> Vec<Self::Item>
    where
        Self: Sized,
        F: Fn(&Self::Item, &Self::Item) -> Option<Ordering>;

    fn partial_max(self) -> Vec<Self::Item>
    where
        Self: Sized,
        Self::Item: PartialOrd,
    {
        self.partial_max_by(|left, right| left.partial_cmp(right))
    }
}

impl<T> PartialMax for T
where
    T: Iterator,
{
    fn partial_max_by<F>(self, partial_cmp: F) -> Vec<Self::Item>
    where
        Self: Sized,
        F: Fn(&Self::Item, &Self::Item) -> Option<Ordering>,
    {
        self.fold(vec![], |pmax, elem| {
            let (mut result, has_new_max): (Vec<_>, bool) = pmax
                .into_iter()
                .map(|max| match partial_cmp(&max, &elem) {
                    Some(ord) => match ord {
                        std::cmp::Ordering::Less => (None, true),
                        std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                            (Some(max), false)
                        }
                    },
                    None => (Some(max), true),
                })
                .fold((vec![], false), |(mut acc, has_new_max), max| {
                    if let Some(max) = max.0 {
                        acc.push(max)
                    }
                    (acc, has_new_max || max.1)
                });
            if has_new_max || result.is_empty() {
                result.push(elem);
            }
            result
        })
    }
}

/// Spinning timeout check for the standard `std::process::Child` type.
pub trait ChildWait {
    /// Wait for this child to exit, timing out after the duration `timeout` has
    /// elapsed.
    ///
    /// If `None` is returned then the timeout period elapsed without the
    /// child exiting and the child has been killed,
    /// and if `Some(exit_code)` is returned then the child exited
    /// with the specified exit code.
    fn wait_timeout(&mut self, timeout: Duration) -> Option<ExitStatus>;
}

impl ChildWait for Child {
    fn wait_timeout(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let start = Instant::now();
        let mut exited: bool = false;
        let mut wait = None;
        while start.elapsed() < timeout {
            wait = self.try_wait().expect("Error: failure in try_wait()");
            match wait {
                Some(_) => {
                    exited = true;
                    break;
                }
                None => {
                    sleep(Duration::from_millis(100));
                }
            }
        }
        if !exited {
            self.kill().expect("Error: failure in kill()");
            return None;
        }
        wait
    }
}
