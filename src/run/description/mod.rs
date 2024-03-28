use self::runs::Runs;

pub mod runs;
pub mod tools;

pub fn run_count(runs: &Runs) -> usize {
    let mut result: usize = 0;
    for run in runs.runs.iter() {
        result += run.roots.len() * run.tools.len();
    }
    result
}
