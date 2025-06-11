use crate::parser::{LogEntry, LogType, parse_log_line, group_by_ip, group_by_user_agent, filter_errors, 
    filter_by_http_status, filter_by_time_range, detect_injection_attempts,
    filter_sql_injection_attempts, filter_xss_attempts, filter_path_traversal_attempts,
    filter_command_injection_attempts, filter_nosql_injection_attempts, filter_ldap_injection_attempts,
    filter_xxe_injection_attempts, filter_ssti_injection_attempts, filter_log_poisoning_attempts,
    filter_header_injection_attempts, filter_ssrf_attack_attempts, filter_suspicious_user_agents};
use eframe::egui;
use egui_extras::{Column, TableBuilder}; // <--- Hinzufügen
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::collections::HashMap;

// Struct to hold time picker state
struct TimePicker {
    show: bool,
    is_start_time: bool,
    hour: u32,
    minute: u32,
    second: u32,
}

impl Default for TimePicker {
    fn default() -> Self {
        Self {
            show: false,
            is_start_time: true,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }
}

pub struct MyApp {
    log_entries: Vec<LogEntry>,
    filtered_entries: Vec<LogEntry>,
    grouped_by_ip: HashMap<String, Vec<LogEntry>>,
    grouped_by_user_agent: HashMap<String, Vec<LogEntry>>,
    error_message: Option<String>,
    show_errors_only: bool,
    current_grouping: Grouping,
    selected_group_key: Option<String>,
    sort_by: SortBy,
    sort_ascending: bool,
    http_status_filter: Option<u16>,
    time_filter_start: Option<String>, // Format: HH:MM:SS
    time_filter_end: Option<String>,   // Format: HH:MM:SS
    show_injection_attempts: bool,
    show_specific_injection_filters: bool,
    filter_sql_injection: bool,
    filter_xss: bool,
    filter_path_traversal: bool,
    filter_command_injection: bool,
    filter_nosql_injection: bool,
    filter_ldap_injection: bool,
    filter_xxe_injection: bool,
    filter_ssti_injection: bool,
    filter_log_poisoning: bool,
    filter_header_injection: bool,
    filter_ssrf_attack: bool,
    filter_suspicious_user_agent: bool,
    detected_log_type: Option<LogType>, // Speichert den erkannten Log-Typ (Access oder Error)
    time_picker: TimePicker, // Time picker dialog state
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            log_entries: Vec::new(),
            filtered_entries: Vec::new(),
            grouped_by_ip: HashMap::new(),
            grouped_by_user_agent: HashMap::new(),
            error_message: None,
            show_errors_only: false,
            current_grouping: Grouping::default(),
            selected_group_key: None,
            sort_by: SortBy::default(),
            sort_ascending: true,
            http_status_filter: None,
            time_filter_start: None,
            time_filter_end: None,
            show_injection_attempts: false,
            show_specific_injection_filters: false,
            filter_sql_injection: false,
            filter_xss: false,
            filter_path_traversal: false,
            filter_command_injection: false,
            filter_nosql_injection: false,
            filter_ldap_injection: false,
            filter_xxe_injection: false,
            filter_ssti_injection: false,
            filter_log_poisoning: false,
            filter_header_injection: false,
            filter_ssrf_attack: false,
            filter_suspicious_user_agent: false,
            detected_log_type: None,
            time_picker: TimePicker::default(),
        }
    }
}

#[derive(Default, PartialEq, Clone, Copy)]
enum Grouping {
    #[default]
    None,
    ByIp,
    ByUserAgent,
}

#[derive(Default, PartialEq, Clone, Copy)]
enum SortBy {
    #[default]
    None,
    Timestamp,
    IpAddress,
    Method,
    Path,
    StatusCode,
    UserAgent,
}

impl MyApp {
    // Helper method to determine if we're dealing with an access log or error log
    fn is_access_log(&self) -> bool {
        match self.detected_log_type {
            Some(LogType::Access) => true,
            Some(LogType::Error) => false,
            None => true, // Default to access log if not detected
        }
    }

    // Helper method to handle sorting actions
    fn handle_sort_action(&mut self, sort_by: SortBy) {
        if self.sort_by == sort_by {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_by = sort_by;
            self.sort_ascending = true;
        }
        self.apply_filters_and_grouping();
    }

    // Helper method to check if any specific injection filter is active
    fn any_injection_filter_active(&self) -> bool {
        self.filter_sql_injection || 
        self.filter_xss || 
        self.filter_path_traversal || 
        self.filter_command_injection || 
        self.filter_nosql_injection || 
        self.filter_ldap_injection || 
        self.filter_xxe_injection || 
        self.filter_ssti_injection || 
        self.filter_log_poisoning || 
        self.filter_header_injection || 
        self.filter_ssrf_attack || 
        self.filter_suspicious_user_agent
    }

    // Helper method to show the time picker dialog
    fn show_time_picker_dialog(&mut self, ctx: &egui::Context) {
        if self.time_picker.show {
            let mut open = true;
            let title = if self.time_picker.is_start_time {
                "Startzeit auswählen"
            } else {
                "Endzeit auswählen"
            };

            egui::Window::new(title)
                .open(&mut open)
                .resizable(false)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Stunde:");
                        ui.add(egui::Slider::new(&mut self.time_picker.hour, 0..=23).text(""));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Minute:");
                        ui.add(egui::Slider::new(&mut self.time_picker.minute, 0..=59).text(""));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Sekunde:");
                        ui.add(egui::Slider::new(&mut self.time_picker.second, 0..=59).text(""));
                    });

                    ui.separator();

                    ui.horizontal(|ui| {
                        if ui.button("Abbrechen").clicked() {
                            self.time_picker.show = false;
                        }

                        if ui.button("Übernehmen").clicked() {
                            let time_str = format!(
                                "{:02}:{:02}:{:02}", 
                                self.time_picker.hour, 
                                self.time_picker.minute, 
                                self.time_picker.second
                            );

                            if self.time_picker.is_start_time {
                                self.time_filter_start = Some(time_str);
                                if self.time_filter_end.is_none() {
                                    self.time_filter_end = Some("23:59:59".to_string());
                                }
                            } else {
                                self.time_filter_end = Some(time_str);
                                if self.time_filter_start.is_none() {
                                    self.time_filter_start = Some("00:00:00".to_string());
                                }
                            }

                            self.apply_filters_and_grouping();
                            self.time_picker.show = false;
                        }
                    });
                });

            if !open {
                self.time_picker.show = false;
            }
        }
    }

    fn load_log_file(&mut self, path: PathBuf) {
        self.log_entries.clear();
        self.filtered_entries.clear(); // Auch gefilterte Liste leeren
        self.grouped_by_ip.clear();
        self.grouped_by_user_agent.clear();
        self.selected_group_key = None;
        self.error_message = None;
        self.sort_by = SortBy::None;
        self.sort_ascending = true;
        self.http_status_filter = None;
        self.time_filter_start = None;
        self.time_filter_end = None;
        self.show_injection_attempts = false;
        self.detected_log_type = None;

        // Reset time picker state
        self.time_picker.show = false;
        self.time_picker.is_start_time = true;
        self.time_picker.hour = 0;
        self.time_picker.minute = 0;
        self.time_picker.second = 0;

        match File::open(path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    match line {
                        Ok(l) => {
                            if let Some(entry) = parse_log_line(&l) {
                                // Wenn wir noch keinen Log-Typ erkannt haben, nehmen wir den Typ des ersten Eintrags
                                if self.detected_log_type.is_none() {
                                    self.detected_log_type = Some(entry.log_type.clone());
                                }
                                self.log_entries.push(entry);
                            }
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Fehler beim Lesen der Zeile: {}", e));
                            break;
                        }
                    }
                }

                // Wenn keine Einträge gefunden wurden, setzen wir den Log-Typ auf Access (Standard)
                if self.log_entries.is_empty() {
                    self.detected_log_type = Some(LogType::Access);
                }

                self.apply_filters_and_grouping();
            }
            Err(e) => {
                self.error_message = Some(format!("Fehler beim Öffnen der Datei: {}", e));
            }
        }
    }

    fn apply_filters_and_grouping(&mut self) {
        let mut entries_to_process = self.log_entries.clone();

        // Apply error filter
        if self.show_errors_only {
            entries_to_process = filter_errors(&entries_to_process);
        }

        // Apply HTTP status filter
        if let Some(status) = self.http_status_filter {
            entries_to_process = filter_by_http_status(&entries_to_process, status);
        }

        // Apply time range filter
        if let (Some(start), Some(end)) = (&self.time_filter_start, &self.time_filter_end) {
            entries_to_process = filter_by_time_range(&entries_to_process, start, end);
        }

        // Filter for injection attempts
        if self.show_injection_attempts {
            if self.show_specific_injection_filters {
                // Apply specific injection type filters
                let mut filtered_entries = Vec::new();

                if self.filter_sql_injection {
                    filtered_entries.extend(filter_sql_injection_attempts(&entries_to_process));
                }

                if self.filter_xss {
                    filtered_entries.extend(filter_xss_attempts(&entries_to_process));
                }

                if self.filter_path_traversal {
                    filtered_entries.extend(filter_path_traversal_attempts(&entries_to_process));
                }

                if self.filter_command_injection {
                    filtered_entries.extend(filter_command_injection_attempts(&entries_to_process));
                }

                if self.filter_nosql_injection {
                    filtered_entries.extend(filter_nosql_injection_attempts(&entries_to_process));
                }

                if self.filter_ldap_injection {
                    filtered_entries.extend(filter_ldap_injection_attempts(&entries_to_process));
                }

                if self.filter_xxe_injection {
                    filtered_entries.extend(filter_xxe_injection_attempts(&entries_to_process));
                }

                if self.filter_ssti_injection {
                    filtered_entries.extend(filter_ssti_injection_attempts(&entries_to_process));
                }

                if self.filter_log_poisoning {
                    filtered_entries.extend(filter_log_poisoning_attempts(&entries_to_process));
                }

                if self.filter_header_injection {
                    filtered_entries.extend(filter_header_injection_attempts(&entries_to_process));
                }

                if self.filter_ssrf_attack {
                    filtered_entries.extend(filter_ssrf_attack_attempts(&entries_to_process));
                }

                if self.filter_suspicious_user_agent {
                    filtered_entries.extend(filter_suspicious_user_agents(&entries_to_process));
                }

                // Remove duplicates
                filtered_entries.sort_by(|a, b| {
                    a.timestamp.cmp(&b.timestamp)
                        .then(a.ip_address.cmp(&b.ip_address))
                        .then(a.path.cmp(&b.path))
                });
                filtered_entries.dedup();

                // If no specific filters are selected, show all injection attempts
                if filtered_entries.is_empty() && !self.any_injection_filter_active() {
                    entries_to_process = detect_injection_attempts(&entries_to_process);
                } else {
                    entries_to_process = filtered_entries;
                }
            } else {
                // Show all injection attempts
                entries_to_process = detect_injection_attempts(&entries_to_process);
            }
        }

        // Apply sorting
        if self.sort_by != SortBy::None {
            entries_to_process.sort_by(|a, b| {
                let cmp = match self.sort_by {
                    SortBy::Timestamp => a.timestamp.cmp(&b.timestamp),
                    SortBy::IpAddress => a.ip_address.cmp(&b.ip_address),
                    SortBy::Method => a.method.cmp(&b.method),
                    SortBy::Path => a.path.cmp(&b.path),
                    SortBy::StatusCode => a.status_code.cmp(&b.status_code),
                    SortBy::UserAgent => a.user_agent.cmp(&b.user_agent),
                    SortBy::None => std::cmp::Ordering::Equal,
                };

                if self.sort_ascending {
                    cmp
                } else {
                    cmp.reverse()
                }
            });
        }

        self.filtered_entries = entries_to_process.clone();

        match self.current_grouping {
            Grouping::None => {
                self.grouped_by_ip.clear();
                self.grouped_by_user_agent.clear();
            }
            Grouping::ByIp => {
                self.grouped_by_ip = group_by_ip(&entries_to_process);
                self.grouped_by_user_agent.clear();
            }
            Grouping::ByUserAgent => {
                self.grouped_by_user_agent = group_by_user_agent(&entries_to_process);
                self.grouped_by_ip.clear();
            }
        }
        self.selected_group_key = None;
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Show time picker dialog if needed
        self.show_time_picker_dialog(ctx);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Apache Log Analyzer");
            ui.separator();

            if ui.button("Logdatei öffnen...").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.load_log_file(path);
                }
            }

            if let Some(err) = &self.error_message {
                ui.colored_label(egui::Color32::RED, err);
            }

            if !self.log_entries.is_empty() {
                ui.separator();

                // Error and Injection filters
                ui.horizontal(|ui| {
                    if ui.toggle_value(&mut self.show_errors_only, "Nur Fehler anzeigen (Status >= 400)").changed() {
                        self.apply_filters_and_grouping();
                    }

                    if ui.toggle_value(&mut self.show_injection_attempts, "Injection-Versuche anzeigen").changed() {
                        self.apply_filters_and_grouping();
                    }

                    if self.show_injection_attempts {
                        if ui.toggle_value(&mut self.show_specific_injection_filters, "Spezifische Injection-Typen filtern").changed() {
                            self.apply_filters_and_grouping();
                        }
                    }
                });

                // Specific Injection Type filters
                if self.show_injection_attempts && self.show_specific_injection_filters {
                    ui.separator();
                    ui.heading("Injection-Typen Filter");

                    ui.columns(3, |columns| {
                        // Column 1
                        if columns[0].checkbox(&mut self.filter_sql_injection, "SQL Injection")
                            .on_hover_text("SQL Injection Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[0].checkbox(&mut self.filter_xss, "XSS (Cross-Site Scripting)")
                            .on_hover_text("Cross-Site Scripting Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[0].checkbox(&mut self.filter_path_traversal, "Path Traversal")
                            .on_hover_text("Path Traversal Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[0].checkbox(&mut self.filter_command_injection, "Command Injection")
                            .on_hover_text("Command Injection Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        // Column 2
                        if columns[1].checkbox(&mut self.filter_nosql_injection, "NoSQL Injection")
                            .on_hover_text("NoSQL Injection Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[1].checkbox(&mut self.filter_ldap_injection, "LDAP Injection")
                            .on_hover_text("LDAP Injection Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[1].checkbox(&mut self.filter_xxe_injection, "XXE Injection")
                            .on_hover_text("XML External Entity Injection Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[1].checkbox(&mut self.filter_ssti_injection, "SSTI Injection")
                            .on_hover_text("Server-Side Template Injection Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        // Column 3
                        if columns[2].checkbox(&mut self.filter_log_poisoning, "Log Poisoning")
                            .on_hover_text("Log Poisoning Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[2].checkbox(&mut self.filter_header_injection, "Header Injection")
                            .on_hover_text("HTTP Header Injection Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[2].checkbox(&mut self.filter_ssrf_attack, "SSRF Attack")
                            .on_hover_text("Server-Side Request Forgery Versuche filtern")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }

                        if columns[2].checkbox(&mut self.filter_suspicious_user_agent, "Verdächtige User-Agents")
                            .on_hover_text("Verdächtige User-Agents filtern (z.B. Scanner, Bots)")
                            .changed() {
                            self.apply_filters_and_grouping();
                        }
                    });

                    ui.separator();
                }

                // HTTP Status filter
                ui.horizontal(|ui| {
                    ui.label("HTTP Status Filter:");
                    let status_codes = [200, 201, 301, 302, 304, 400, 401, 403, 404, 406, 410, 419, 500, 501, 502, 503];

                    if ui.button("Alle").clicked() {
                        self.http_status_filter = None;
                        self.apply_filters_and_grouping();
                    }

                    for &code in &status_codes {
                        let is_selected = self.http_status_filter == Some(code);
                        if ui.selectable_label(is_selected, code.to_string()).clicked() {
                            self.http_status_filter = if is_selected { None } else { Some(code) };
                            self.apply_filters_and_grouping();
                        }
                    }
                });

                // Time range filter
                ui.horizontal(|ui| {
                    ui.label("Zeitfilter:");

                    let start_time_display = self.time_filter_start.clone().unwrap_or_else(|| "00:00:00".to_string());
                    let end_time_display = self.time_filter_end.clone().unwrap_or_else(|| "23:59:59".to_string());

                    // Button to open start time picker
                    if ui.button(format!("Von: {}", start_time_display)).clicked() {
                        // Parse current start time to initialize the picker
                        if let Some(time_str) = &self.time_filter_start {
                            let parts: Vec<&str> = time_str.split(':').collect();
                            if parts.len() == 3 {
                                self.time_picker.hour = parts[0].parse().unwrap_or(0);
                                self.time_picker.minute = parts[1].parse().unwrap_or(0);
                                self.time_picker.second = parts[2].parse().unwrap_or(0);
                            }
                        } else {
                            // Default to 00:00:00
                            self.time_picker.hour = 0;
                            self.time_picker.minute = 0;
                            self.time_picker.second = 0;
                        }
                        self.time_picker.is_start_time = true;
                        self.time_picker.show = true;
                    }

                    ui.label("bis");

                    // Button to open end time picker
                    if ui.button(format!("Bis: {}", end_time_display)).clicked() {
                        // Parse current end time to initialize the picker
                        if let Some(time_str) = &self.time_filter_end {
                            let parts: Vec<&str> = time_str.split(':').collect();
                            if parts.len() == 3 {
                                self.time_picker.hour = parts[0].parse().unwrap_or(23);
                                self.time_picker.minute = parts[1].parse().unwrap_or(59);
                                self.time_picker.second = parts[2].parse().unwrap_or(59);
                            }
                        } else {
                            // Default to 23:59:59
                            self.time_picker.hour = 23;
                            self.time_picker.minute = 59;
                            self.time_picker.second = 59;
                        }
                        self.time_picker.is_start_time = false;
                        self.time_picker.show = true;
                    }

                    if ui.button("Zurücksetzen").clicked() {
                        self.time_filter_start = None;
                        self.time_filter_end = None;
                        self.apply_filters_and_grouping();
                    }
                });

                // Grouping options
                ui.horizontal(|ui| {
                    ui.label("Gruppieren nach:");
                    if ui.selectable_value(&mut self.current_grouping, Grouping::None, "Keine").changed() {
                        self.apply_filters_and_grouping();
                    }
                    if ui.selectable_value(&mut self.current_grouping, Grouping::ByIp, "IP Adresse").changed() {
                        self.apply_filters_and_grouping();
                    }
                    if ui.selectable_value(&mut self.current_grouping, Grouping::ByUserAgent, "User Agent").changed() {
                        self.apply_filters_and_grouping();
                    }
                });
                ui.separator();

                // --- ANFANG TABELLENANZEIGE ---
                let table_height = ui.available_height() - 50.0; // Etwas Platz für andere UI-Elemente lassen

                match self.current_grouping {
                    Grouping::None => {
                        if self.is_access_log() {
                            // Access Log Tabelle
                            TableBuilder::new(ui)
                                .striped(true)
                                .resizable(true)
                                .column(Column::auto().at_least(150.0)) // Timestamp
                                .column(Column::auto().at_least(100.0)) // IP
                                .column(Column::auto().at_least(50.0))  // Method
                                .column(Column::remainder().at_least(200.0)) // Path
                                .column(Column::auto().at_least(50.0))  // Status
                                .column(Column::remainder().at_least(200.0)) // User Agent
                                .header(20.0, |mut header| {
                                    header.col(|ui| { 
                                        let text = format!("Zeitstempel {}", if self.sort_by == SortBy::Timestamp { 
                                            if self.sort_ascending { "↑" } else { "↓" } 
                                        } else { "" });
                                        if ui.button(text).clicked() {
                                            if self.sort_by == SortBy::Timestamp {
                                                self.sort_ascending = !self.sort_ascending;
                                            } else {
                                                self.sort_by = SortBy::Timestamp;
                                                self.sort_ascending = true;
                                            }
                                            self.apply_filters_and_grouping();
                                        }
                                    });
                                    header.col(|ui| { 
                                        let text = format!("IP Adresse {}", if self.sort_by == SortBy::IpAddress { 
                                            if self.sort_ascending { "↑" } else { "↓" } 
                                        } else { "" });
                                        if ui.button(text).clicked() {
                                            if self.sort_by == SortBy::IpAddress {
                                                self.sort_ascending = !self.sort_ascending;
                                            } else {
                                                self.sort_by = SortBy::IpAddress;
                                                self.sort_ascending = true;
                                            }
                                            self.apply_filters_and_grouping();
                                        }
                                    });
                                    header.col(|ui| { 
                                        let text = format!("Methode {}", if self.sort_by == SortBy::Method { 
                                            if self.sort_ascending { "↑" } else { "↓" } 
                                        } else { "" });
                                        if ui.button(text).clicked() {
                                            if self.sort_by == SortBy::Method {
                                                self.sort_ascending = !self.sort_ascending;
                                            } else {
                                                self.sort_by = SortBy::Method;
                                                self.sort_ascending = true;
                                            }
                                            self.apply_filters_and_grouping();
                                        }
                                    });
                                    header.col(|ui| { 
                                        let text = format!("Pfad {}", if self.sort_by == SortBy::Path { 
                                            if self.sort_ascending { "↑" } else { "↓" } 
                                        } else { "" });
                                        if ui.button(text).clicked() {
                                            if self.sort_by == SortBy::Path {
                                                self.sort_ascending = !self.sort_ascending;
                                            } else {
                                                self.sort_by = SortBy::Path;
                                                self.sort_ascending = true;
                                            }
                                            self.apply_filters_and_grouping();
                                        }
                                    });
                                    header.col(|ui| { 
                                        let text = format!("Status {}", if self.sort_by == SortBy::StatusCode { 
                                            if self.sort_ascending { "↑" } else { "↓" } 
                                        } else { "" });
                                        if ui.button(text).clicked() {
                                            if self.sort_by == SortBy::StatusCode {
                                                self.sort_ascending = !self.sort_ascending;
                                            } else {
                                                self.sort_by = SortBy::StatusCode;
                                                self.sort_ascending = true;
                                            }
                                            self.apply_filters_and_grouping();
                                        }
                                    });
                                    header.col(|ui| { 
                                        let text = format!("User Agent {}", if self.sort_by == SortBy::UserAgent { 
                                            if self.sort_ascending { "↑" } else { "↓" } 
                                        } else { "" });
                                        if ui.button(text).clicked() {
                                            if self.sort_by == SortBy::UserAgent {
                                                self.sort_ascending = !self.sort_ascending;
                                            } else {
                                                self.sort_by = SortBy::UserAgent;
                                                self.sort_ascending = true;
                                            }
                                            self.apply_filters_and_grouping();
                                        }
                                    });
                                })
                                .body(|body| {
                                    body.rows(20.0, self.filtered_entries.len(), |mut row| {
                                        let entry = &self.filtered_entries[row.index()];
                                        row.col(|ui| { ui.label(&entry.timestamp); });
                                        row.col(|ui| { ui.label(&entry.ip_address); });
                                        row.col(|ui| { ui.label(&entry.method); });
                                        row.col(|ui| { ui.label(&entry.path); });
                                        row.col(|ui| { ui.label(entry.status_code.to_string()); });
                                        row.col(|ui| { ui.label(&entry.user_agent).on_hover_text(&entry.user_agent); }); // Hover für lange UAs
                                    });
                                });
                        } else {
                            // Error Log Tabelle
                            TableBuilder::new(ui)
                                .striped(true)
                                .resizable(true)
                                .column(Column::auto().at_least(150.0)) // Timestamp
                                .column(Column::auto().at_least(80.0))  // Level
                                .column(Column::auto().at_least(100.0)) // Module
                                .column(Column::auto().at_least(100.0)) // IP (optional)
                                .column(Column::remainder().at_least(300.0)) // Message
                                .header(20.0, |mut header| {
                                    header.col(|ui| { 
                                        let text = format!("Zeitstempel {}", if self.sort_by == SortBy::Timestamp { 
                                            if self.sort_ascending { "↑" } else { "↓" } 
                                        } else { "" });
                                        if ui.button(text).clicked() {
                                            if self.sort_by == SortBy::Timestamp {
                                                self.sort_ascending = !self.sort_ascending;
                                            } else {
                                                self.sort_by = SortBy::Timestamp;
                                                self.sort_ascending = true;
                                            }
                                            self.apply_filters_and_grouping();
                                        }
                                    });
                                    header.col(|ui| { ui.strong("Level"); });
                                    header.col(|ui| { ui.strong("Modul"); });
                                    header.col(|ui| { 
                                        let text = format!("IP Adresse {}", if self.sort_by == SortBy::IpAddress { 
                                            if self.sort_ascending { "↑" } else { "↓" } 
                                        } else { "" });
                                        if ui.button(text).clicked() {
                                            if self.sort_by == SortBy::IpAddress {
                                                self.sort_ascending = !self.sort_ascending;
                                            } else {
                                                self.sort_by = SortBy::IpAddress;
                                                self.sort_ascending = true;
                                            }
                                            self.apply_filters_and_grouping();
                                        }
                                    });
                                    header.col(|ui| { ui.strong("Fehlermeldung"); });
                                })
                                .body(|body| {
                                    body.rows(20.0, self.filtered_entries.len(), |mut row| {
                                        let entry = &self.filtered_entries[row.index()];
                                        row.col(|ui| { ui.label(&entry.timestamp); });
                                        row.col(|ui| { ui.label(&entry.level); });
                                        row.col(|ui| { ui.label(&entry.module); });
                                        row.col(|ui| { ui.label(&entry.ip_address); });
                                        row.col(|ui| { ui.label(&entry.message).on_hover_text(&entry.message); });
                                    });
                                });
                        }
                    }
                    Grouping::ByIp => {
                        // Flag to track if sorting has changed
                        let mut sorting_changed = false;
                        let mut new_sort_by = self.sort_by;
                        let mut new_sort_ascending = self.sort_ascending;

                        egui::ScrollArea::vertical().max_height(table_height).show(ui, |ui| {
                            for (ip, entries) in &self.grouped_by_ip {
                                if ui.selectable_label(self.selected_group_key.as_ref() == Some(ip), format!("IP: {} ({} Einträge)", ip, entries.len())).clicked() {
                                    self.selected_group_key = Some(ip.clone());
                                }
                                if self.selected_group_key.as_ref() == Some(ip) {
                                    ui.indent("details_ip", |ui| {
                                        if self.is_access_log() {
                                            // Access Log Tabelle für IP-Gruppierung
                                            TableBuilder::new(ui)
                                                .striped(true)
                                                .column(Column::auto().at_least(150.0)) // Timestamp
                                                .column(Column::auto().at_least(50.0))  // Method
                                                .column(Column::remainder().at_least(200.0)) // Path
                                                .column(Column::auto().at_least(50.0))  // Status
                                                .column(Column::remainder().at_least(150.0)) // User Agent (gekürzt)
                                                .header(20.0, |mut header| {
                                                    header.col(|ui| { 
                                                        let text = format!("Zeitstempel {}", if new_sort_by == SortBy::Timestamp { 
                                                            if new_sort_ascending { "↑" } else { "↓" } 
                                                        } else { "" });
                                                        if ui.button(text).clicked() {
                                                            if new_sort_by == SortBy::Timestamp {
                                                                new_sort_ascending = !new_sort_ascending;
                                                            } else {
                                                                new_sort_by = SortBy::Timestamp;
                                                                new_sort_ascending = true;
                                                            }
                                                            sorting_changed = true;
                                                            ui.ctx().request_repaint();
                                                        }
                                                    });
                                                    header.col(|ui| { 
                                                        let text = format!("Methode {}", if new_sort_by == SortBy::Method { 
                                                            if new_sort_ascending { "↑" } else { "↓" } 
                                                        } else { "" });
                                                        if ui.button(text).clicked() {
                                                            if new_sort_by == SortBy::Method {
                                                                new_sort_ascending = !new_sort_ascending;
                                                            } else {
                                                                new_sort_by = SortBy::Method;
                                                                new_sort_ascending = true;
                                                            }
                                                            sorting_changed = true;
                                                            ui.ctx().request_repaint();
                                                        }
                                                    });
                                                    header.col(|ui| { 
                                                        let text = format!("Pfad {}", if new_sort_by == SortBy::Path { 
                                                            if new_sort_ascending { "↑" } else { "↓" } 
                                                        } else { "" });
                                                        if ui.button(text).clicked() {
                                                            if new_sort_by == SortBy::Path {
                                                                new_sort_ascending = !new_sort_ascending;
                                                            } else {
                                                                new_sort_by = SortBy::Path;
                                                                new_sort_ascending = true;
                                                            }
                                                            sorting_changed = true;
                                                            ui.ctx().request_repaint();
                                                        }
                                                    });
                                                    header.col(|ui| { 
                                                        let text = format!("Status {}", if new_sort_by == SortBy::StatusCode { 
                                                            if new_sort_ascending { "↑" } else { "↓" } 
                                                        } else { "" });
                                                        if ui.button(text).clicked() {
                                                            if new_sort_by == SortBy::StatusCode {
                                                                new_sort_ascending = !new_sort_ascending;
                                                            } else {
                                                                new_sort_by = SortBy::StatusCode;
                                                                new_sort_ascending = true;
                                                            }
                                                            sorting_changed = true;
                                                            ui.ctx().request_repaint();
                                                        }
                                                    });
                                                    header.col(|ui| { 
                                                        let text = format!("User Agent {}", if new_sort_by == SortBy::UserAgent { 
                                                            if new_sort_ascending { "↑" } else { "↓" } 
                                                        } else { "" });
                                                        if ui.button(text).clicked() {
                                                            if new_sort_by == SortBy::UserAgent {
                                                                new_sort_ascending = !new_sort_ascending;
                                                            } else {
                                                                new_sort_by = SortBy::UserAgent;
                                                                new_sort_ascending = true;
                                                            }
                                                            sorting_changed = true;
                                                            ui.ctx().request_repaint();
                                                        }
                                                    });
                                                })
                                                .body(|body| {
                                                    let num_rows = entries.len();
                                                    body.rows(20.0, num_rows, |mut row| {
                                                        let entry = &entries[row.index()];
                                                        row.col(|ui| { ui.label(&entry.timestamp); });
                                                        row.col(|ui| { ui.label(&entry.method); });
                                                        row.col(|ui| { ui.label(&entry.path); });
                                                        row.col(|ui| { ui.label(entry.status_code.to_string()); });
                                                        row.col(|ui| {
                                                            let ua_display = if entry.user_agent.len() > 50 {
                                                                format!("{}...", &entry.user_agent[..50])
                                                            } else {
                                                                entry.user_agent.clone()
                                                            };
                                                            ui.label(ua_display).on_hover_text(&entry.user_agent);
                                                        });
                                                    });
                                                });
                                        } else {
                                            // Error Log Tabelle für IP-Gruppierung
                                            TableBuilder::new(ui)
                                                .striped(true)
                                                .column(Column::auto().at_least(150.0)) // Timestamp
                                                .column(Column::auto().at_least(80.0))  // Level
                                                .column(Column::auto().at_least(100.0)) // Module
                                                .column(Column::remainder().at_least(300.0)) // Message
                                                .header(20.0, |mut header| {
                                                    header.col(|ui| { 
                                                        let text = format!("Zeitstempel {}", if new_sort_by == SortBy::Timestamp { 
                                                            if new_sort_ascending { "↑" } else { "↓" } 
                                                        } else { "" });
                                                        if ui.button(text).clicked() {
                                                            if new_sort_by == SortBy::Timestamp {
                                                                new_sort_ascending = !new_sort_ascending;
                                                            } else {
                                                                new_sort_by = SortBy::Timestamp;
                                                                new_sort_ascending = true;
                                                            }
                                                            sorting_changed = true;
                                                            ui.ctx().request_repaint();
                                                        }
                                                    });
                                                    header.col(|ui| { ui.strong("Level"); });
                                                    header.col(|ui| { ui.strong("Modul"); });
                                                    header.col(|ui| { ui.strong("Fehlermeldung"); });
                                                })
                                                .body(|body| {
                                                    let num_rows = entries.len();
                                                    body.rows(20.0, num_rows, |mut row| {
                                                        let entry = &entries[row.index()];
                                                        row.col(|ui| { ui.label(&entry.timestamp); });
                                                        row.col(|ui| { ui.label(&entry.level); });
                                                        row.col(|ui| { ui.label(&entry.module); });
                                                        row.col(|ui| { ui.label(&entry.message).on_hover_text(&entry.message); });
                                                    });
                                                });
                                        }
                                    });
                                }
                            }
                        });

                        // Apply sorting changes after the loop if needed
                        if sorting_changed {
                            self.sort_by = new_sort_by;
                            self.sort_ascending = new_sort_ascending;
                            self.apply_filters_and_grouping();
                        }
                    }
                    Grouping::ByUserAgent => {
                        egui::ScrollArea::vertical().max_height(table_height).show(ui, |ui| {
                            for (ua, entries) in &self.grouped_by_user_agent {
                                let display_ua = if ua.len() > 70 { format!("{}...", &ua[..70]) } else { ua.clone() };
                                if ui.selectable_label(self.selected_group_key.as_ref() == Some(ua), format!("User Agent: {} ({} Einträge)", display_ua, entries.len())).clicked() {
                                    self.selected_group_key = Some(ua.clone());
                                }
                                if self.selected_group_key.as_ref() == Some(ua) {
                                    ui.indent("details_ua", |ui| {
                                        if self.is_access_log() {
                                            // Access Log Tabelle für UserAgent-Gruppierung
                                            TableBuilder::new(ui)
                                                .striped(true)
                                                .column(Column::auto().at_least(150.0)) // Timestamp
                                                .column(Column::auto().at_least(100.0)) // IP
                                                .column(Column::auto().at_least(50.0))  // Method
                                                .column(Column::remainder().at_least(200.0)) // Path
                                                .column(Column::auto().at_least(50.0))  // Status
                                                .header(20.0, |mut header| {
                                                    header.col(|ui| { ui.strong("Zeitstempel"); });
                                                    header.col(|ui| { ui.strong("IP Adresse"); });
                                                    header.col(|ui| { ui.strong("Methode"); });
                                                    header.col(|ui| { ui.strong("Pfad"); });
                                                    header.col(|ui| { ui.strong("Status"); });
                                                })
                                                .body(|body| {
                                                    let num_rows = entries.len();
                                                    body.rows(20.0, num_rows, |mut row| {
                                                        let entry = &entries[row.index()];
                                                        row.col(|ui| { ui.label(&entry.timestamp); });
                                                        row.col(|ui| { ui.label(&entry.ip_address); });
                                                        row.col(|ui| { ui.label(&entry.method); });
                                                        row.col(|ui| { ui.label(&entry.path); });
                                                        row.col(|ui| { ui.label(entry.status_code.to_string()); });
                                                    });
                                                });
                                        } else {
                                            // Error Log Tabelle für UserAgent-Gruppierung
                                            TableBuilder::new(ui)
                                                .striped(true)
                                                .column(Column::auto().at_least(150.0)) // Timestamp
                                                .column(Column::auto().at_least(100.0)) // IP
                                                .column(Column::auto().at_least(80.0))  // Level
                                                .column(Column::auto().at_least(100.0)) // Module
                                                .column(Column::remainder().at_least(300.0)) // Message
                                                .header(20.0, |mut header| {
                                                    header.col(|ui| { ui.strong("Zeitstempel"); });
                                                    header.col(|ui| { ui.strong("IP Adresse"); });
                                                    header.col(|ui| { ui.strong("Level"); });
                                                    header.col(|ui| { ui.strong("Modul"); });
                                                    header.col(|ui| { ui.strong("Fehlermeldung"); });
                                                })
                                                .body(|body| {
                                                    let num_rows = entries.len();
                                                    body.rows(20.0, num_rows, |mut row| {
                                                        let entry = &entries[row.index()];
                                                        row.col(|ui| { ui.label(&entry.timestamp); });
                                                        row.col(|ui| { ui.label(&entry.ip_address); });
                                                        row.col(|ui| { ui.label(&entry.level); });
                                                        row.col(|ui| { ui.label(&entry.module); });
                                                        row.col(|ui| { ui.label(&entry.message).on_hover_text(&entry.message); });
                                                    });
                                                });
                                        }
                                    });
                                }
                            }
                        });
                    }
                }
                // --- ENDE TABELLENANZEIGE ---
            }
        });
    }
}
