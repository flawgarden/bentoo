#[derive(Clone, Copy, Debug)]
pub struct ReportConfig {
    pub detailed: bool,
    pub collect_max_result_cards: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            detailed: false,
            collect_max_result_cards: false,
        }
    }
}
