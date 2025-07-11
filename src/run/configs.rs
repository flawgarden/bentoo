#[derive(Clone, Copy, Debug, Default)]
pub struct ReportConfig {
    pub detailed: bool,
    pub collect_max_result_cards: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RunConfig {
    pub isolate_root: bool,
    pub skip_failed: bool,
}
