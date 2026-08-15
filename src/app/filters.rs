//! Issue triage: severity and module filtering, live search, and selection.
//!
//! Self-contained and pure — every function here reads and writes `App` fields
//! without touching the filesystem, the network or a child process, which is
//! what makes this the easiest part of the app to unit test.

use super::state::App;
use crate::engine::issue::Severity;

impl App {
    /// Indices into `self.issues` that survive the active filters and search.
    pub fn filtered_issue_indices(&self) -> Vec<usize> {
        self.issues
            .iter()
            .enumerate()
            .filter(|(_idx, issue)| {
                // Severity filter
                if let Some(sev) = self.severity_filter
                    && issue.severity != sev
                {
                    return false;
                }
                // Module filter
                if let Some(ref mod_id) = self.module_filter
                    && &issue.module_id != mod_id
                {
                    return false;
                }
                // Search query
                if !self.search_query.is_empty() {
                    let q = self.search_query.to_lowercase();
                    let matches_title = issue.title.to_lowercase().contains(&q);
                    let matches_desc = issue.description.to_lowercase().contains(&q);
                    let matches_cat = issue.category.to_lowercase().contains(&q);
                    let matches_mod = issue.module_id.to_lowercase().contains(&q);
                    let matches_tech = issue.technical_details.to_lowercase().contains(&q);
                    if !matches_title
                        && !matches_desc
                        && !matches_cat
                        && !matches_mod
                        && !matches_tech
                    {
                        return false;
                    }
                }
                true
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    pub fn clamp_filtered_selection(&mut self) {
        let count = self.filtered_issue_indices().len();
        if count == 0 {
            self.selected_filtered_index = 0;
        } else if self.selected_filtered_index >= count {
            self.selected_filtered_index = count - 1;
        }
    }

    pub fn toggle_selected_issue(&mut self) {
        let indices = self.filtered_issue_indices();
        if let Some(&orig_idx) = indices.get(self.selected_filtered_index)
            && let Some(issue) = self.issues.get_mut(orig_idx)
            && !issue.is_fixed
        {
            issue.is_selected = !issue.is_selected;
        }
    }

    pub fn select_all_issues(&mut self) {
        let indices = self.filtered_issue_indices();
        for &orig_idx in &indices {
            if let Some(issue) = self.issues.get_mut(orig_idx)
                && !issue.is_fixed
            {
                issue.is_selected = true;
            }
        }
    }

    pub fn deselect_all_issues(&mut self) {
        let indices = self.filtered_issue_indices();
        for &orig_idx in &indices {
            if let Some(issue) = self.issues.get_mut(orig_idx) {
                issue.is_selected = false;
            }
        }
    }

    pub fn next_issue(&mut self) {
        let indices = self.filtered_issue_indices();
        if !indices.is_empty() {
            self.selected_filtered_index = (self.selected_filtered_index + 1) % indices.len();
        }
    }

    pub fn prev_issue(&mut self) {
        let indices = self.filtered_issue_indices();
        if !indices.is_empty() {
            if self.selected_filtered_index == 0 {
                self.selected_filtered_index = indices.len() - 1;
            } else {
                self.selected_filtered_index -= 1;
            }
        }
    }

    pub fn toggle_severity_filter(&mut self, sev: Severity) {
        if self.severity_filter == Some(sev) {
            self.severity_filter = None;
        } else {
            self.severity_filter = Some(sev);
        }
        self.clamp_filtered_selection();
    }

    pub fn cycle_module_filter(&mut self) {
        let mut module_ids: Vec<String> = self
            .engine
            .modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect();
        module_ids.dedup();

        if module_ids.is_empty() {
            self.module_filter = None;
            return;
        }

        self.module_filter = match &self.module_filter {
            None => Some(module_ids[0].clone()),
            Some(current) => {
                if let Some(pos) = module_ids.iter().position(|m| m == current) {
                    if pos + 1 < module_ids.len() {
                        Some(module_ids[pos + 1].clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };
        self.clamp_filtered_selection();
    }

    pub fn clear_filters(&mut self) {
        self.severity_filter = None;
        self.module_filter = None;
        self.search_query.clear();
        self.is_searching = false;
        self.clamp_filtered_selection();
    }

    pub fn has_active_filters(&self) -> bool {
        self.severity_filter.is_some()
            || self.module_filter.is_some()
            || !self.search_query.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::issue::{Issue, RiskScore};

    fn issue(id: &str, module: &str, title: &str, category: &str, severity: Severity) -> Issue {
        Issue::new(
            id,
            module,
            title,
            category,
            severity,
            RiskScore::Low,
            "description",
            "details",
            "fix",
            vec![],
        )
    }

    fn app_with_issues() -> App {
        let mut app = App::new();
        app.issues = vec![
            issue(
                "sfc_1",
                "system_integrity",
                "CBS log corrupt",
                "System",
                Severity::Critical,
            ),
            issue(
                "temp_1",
                "storage",
                "Temp bloat files",
                "Storage",
                Severity::Warning,
            ),
            issue(
                "net_1",
                "network",
                "DNS cache full",
                "Network",
                Severity::Info,
            ),
        ];
        app
    }

    #[test]
    fn test_app_filter_and_search() {
        let mut app = app_with_issues();

        // Initially all 3 are returned
        assert_eq!(app.filtered_issue_indices(), vec![0, 1, 2]);

        // Filter by Critical
        app.toggle_severity_filter(Severity::Critical);
        assert_eq!(app.filtered_issue_indices(), vec![0]);

        // Toggle again to reset severity filter
        app.toggle_severity_filter(Severity::Critical);
        assert_eq!(app.filtered_issue_indices(), vec![0, 1, 2]);

        // Filter by module
        app.module_filter = Some("storage".to_string());
        assert_eq!(app.filtered_issue_indices(), vec![1]);

        // Search text
        app.clear_filters();
        app.search_query = "DNS".to_string();
        assert_eq!(app.filtered_issue_indices(), vec![2]);

        app.clear_filters();
        assert_eq!(app.filtered_issue_indices(), vec![0, 1, 2]);
    }

    #[test]
    fn selection_is_clamped_when_a_filter_shrinks_the_list() {
        let mut app = app_with_issues();
        app.selected_filtered_index = 2;

        // Narrowing to one result must not leave the cursor pointing past the end.
        app.toggle_severity_filter(Severity::Critical);
        assert_eq!(app.selected_filtered_index, 0);
        assert_eq!(app.filtered_issue_indices().len(), 1);
    }

    #[test]
    fn selection_wraps_in_both_directions() {
        let mut app = app_with_issues();
        assert_eq!(app.selected_filtered_index, 0);

        app.prev_issue();
        assert_eq!(
            app.selected_filtered_index, 2,
            "backwards from the top wraps"
        );

        app.next_issue();
        assert_eq!(
            app.selected_filtered_index, 0,
            "forwards from the end wraps"
        );
    }

    #[test]
    fn navigation_on_an_empty_result_set_does_not_panic() {
        let mut app = app_with_issues();
        app.search_query = "nothing matches this".to_string();
        app.clamp_filtered_selection();

        app.next_issue();
        app.prev_issue();
        app.toggle_selected_issue();
        assert_eq!(app.selected_filtered_index, 0);
    }

    #[test]
    fn bulk_selection_only_touches_the_filtered_subset() {
        let mut app = app_with_issues();
        app.deselect_all_issues();
        assert!(app.issues.iter().all(|i| !i.is_selected));

        // With a filter active, select-all is scoped to what is visible.
        app.toggle_severity_filter(Severity::Warning);
        app.select_all_issues();

        assert!(!app.issues[0].is_selected, "critical stays untouched");
        assert!(app.issues[1].is_selected, "the visible warning is selected");
        assert!(!app.issues[2].is_selected, "info stays untouched");
    }

    #[test]
    fn a_fixed_issue_cannot_be_reselected() {
        let mut app = app_with_issues();
        app.deselect_all_issues();
        app.issues[0].is_fixed = true;

        app.select_all_issues();
        assert!(!app.issues[0].is_selected, "already-fixed issues stay out");

        app.selected_filtered_index = 0;
        app.toggle_selected_issue();
        assert!(!app.issues[0].is_selected);
    }

    #[test]
    fn search_covers_more_than_the_title() {
        let mut app = app_with_issues();

        app.search_query = "Storage".to_string(); // category
        assert_eq!(app.filtered_issue_indices(), vec![1]);

        app.search_query = "system_integrity".to_string(); // module id
        assert_eq!(app.filtered_issue_indices(), vec![0]);

        app.search_query = "DETAILS".to_string(); // technical details, case-insensitive
        assert_eq!(app.filtered_issue_indices(), vec![0, 1, 2]);
    }

    #[test]
    fn filters_and_search_compose() {
        let mut app = app_with_issues();
        app.toggle_severity_filter(Severity::Critical);
        app.search_query = "DNS".to_string();

        // The critical issue is not the DNS one, so nothing survives both.
        assert!(app.filtered_issue_indices().is_empty());
    }

    #[test]
    fn has_active_filters_tracks_every_filter_kind() {
        let mut app = app_with_issues();
        assert!(!app.has_active_filters());

        app.toggle_severity_filter(Severity::Info);
        assert!(app.has_active_filters());
        app.clear_filters();

        app.module_filter = Some("network".to_string());
        assert!(app.has_active_filters());
        app.clear_filters();

        app.search_query = "x".to_string();
        assert!(app.has_active_filters());
        app.clear_filters();
        assert!(!app.has_active_filters());
    }
}
