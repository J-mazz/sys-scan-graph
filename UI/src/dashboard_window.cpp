#include "dashboard_window.h"
#include "finding_view.h"
#include <iostream>
#include <filesystem>

namespace SysScanUI {

DashboardWindow::DashboardWindow(GtkApplication* app) : app_(app) {
    agent_ = std::make_unique<AgentInterface>("sys-scan-graph");
    feedback_panel_ = std::make_unique<FeedbackPanel>(window_);
    setup_ui();
}

DashboardWindow::~DashboardWindow() = default;

void DashboardWindow::setup_ui() {
    window_ = gtk_application_window_new(app_);
    gtk_window_set_title(GTK_WINDOW(window_), "sys-scan Security Dashboard");
    gtk_window_set_default_size(GTK_WINDOW(window_), 1200, 800);

    main_box_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(window_), main_box_);

    setup_header_bar();

    // Main content area with paned layout
    content_paned_ = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_vexpand(content_paned_, TRUE);
    gtk_box_append(GTK_BOX(main_box_), content_paned_);

    setup_sidebar();

    // Right side: findings list + detail view + agent panel
    GtkWidget* right_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_vexpand(right_box, TRUE);
    gtk_paned_set_end_child(GTK_PANED(content_paned_), right_box);
    gtk_paned_set_resize_end_child(GTK_PANED(content_paned_), TRUE);

    GtkWidget* findings_detail_paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_vexpand(findings_detail_paned, TRUE);
    gtk_box_append(GTK_BOX(right_box), findings_detail_paned);

    setup_finding_list();
    gtk_paned_set_start_child(GTK_PANED(findings_detail_paned), finding_list_);
    gtk_paned_set_resize_start_child(GTK_PANED(findings_detail_paned), TRUE);

    setup_detail_view();
    gtk_paned_set_end_child(GTK_PANED(findings_detail_paned), detail_view_);
    gtk_paned_set_resize_end_child(GTK_PANED(findings_detail_paned), TRUE);

    setup_agent_query_panel();
    gtk_box_append(GTK_BOX(right_box), agent_panel_);

    // Try to load default report files on startup
    load_default_report();
}

void DashboardWindow::setup_header_bar() {
    header_bar_ = gtk_header_bar_new();
    gtk_window_set_titlebar(GTK_WINDOW(window_), header_bar_);

    GtkWidget* open_button = gtk_button_new_with_label("Open Report");
    g_signal_connect(open_button, "clicked", G_CALLBACK(on_open_clicked), this);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar_), open_button);

    // Search and filter controls
    search_entry_ = gtk_search_entry_new();
    gtk_widget_set_size_request(search_entry_, 250, -1);
    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search_entry_), "Search findings...");
    g_signal_connect(search_entry_, "search-changed", G_CALLBACK(on_filter_changed), this);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header_bar_), search_entry_);
}

void DashboardWindow::setup_sidebar() {
    sidebar_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_size_request(sidebar_, 300, -1);
    gtk_widget_set_vexpand(sidebar_, TRUE);
    gtk_widget_set_margin_start(sidebar_, 12);
    gtk_widget_set_margin_end(sidebar_, 12);
    gtk_widget_set_margin_top(sidebar_, 12);
    gtk_widget_set_margin_bottom(sidebar_, 12);

    GtkWidget* sidebar_title = gtk_label_new("Filters");
    gtk_label_set_xalign(GTK_LABEL(sidebar_title), 0.0);
    gtk_widget_add_css_class(sidebar_title, "title-3");
    gtk_box_append(GTK_BOX(sidebar_), sidebar_title);

    // Severity filter
    GtkWidget* filter_label = gtk_label_new("Severity:");
    gtk_label_set_xalign(GTK_LABEL(filter_label), 0.0);
    gtk_box_append(GTK_BOX(sidebar_), filter_label);

    const char* severities[] = {"All", "Critical", "High", "Medium", "Low", "Info", nullptr};
    GtkStringList* severity_list = gtk_string_list_new(severities);
    severity_dropdown_ = gtk_drop_down_new(G_LIST_MODEL(severity_list), nullptr);
    g_signal_connect(severity_dropdown_, "notify::selected", G_CALLBACK(on_severity_filter_changed), this);
    gtk_box_append(GTK_BOX(sidebar_), severity_dropdown_);

    // Interactive Analysis section
    GtkWidget* analysis_separator = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_append(GTK_BOX(sidebar_), analysis_separator);

    GtkWidget* analysis_title = gtk_label_new("Interactive Analysis");
    gtk_label_set_xalign(GTK_LABEL(analysis_title), 0.0);
    gtk_widget_add_css_class(analysis_title, "title-3");
    gtk_box_append(GTK_BOX(sidebar_), analysis_title);

    GtkWidget* start_analysis_btn = gtk_button_new_with_label("Start Interactive Analysis");
    gtk_widget_add_css_class(start_analysis_btn, "suggested-action");
    g_signal_connect(start_analysis_btn, "clicked", G_CALLBACK(on_start_interactive_analysis_clicked), this);
    gtk_box_append(GTK_BOX(sidebar_), start_analysis_btn);

    // Add feedback panel
    GtkWidget* feedback_widget = feedback_panel_->get_widget();
    gtk_box_append(GTK_BOX(sidebar_), feedback_widget);

    gtk_paned_set_start_child(GTK_PANED(content_paned_), sidebar_);
    gtk_paned_set_resize_start_child(GTK_PANED(content_paned_), FALSE);
}

void DashboardWindow::setup_finding_list() {
    GtkWidget* scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                    GTK_POLICY_AUTOMATIC,
                                    GTK_POLICY_AUTOMATIC);

    finding_list_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), finding_list_);

    finding_list_ = scrolled;
}

void DashboardWindow::setup_detail_view() {
    detail_view_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    GtkWidget* placeholder = gtk_label_new("Select a finding to view details");
    gtk_widget_set_vexpand(placeholder, TRUE);
    gtk_widget_set_hexpand(placeholder, TRUE);
    gtk_box_append(GTK_BOX(detail_view_), placeholder);
}

void DashboardWindow::setup_agent_query_panel() {
    agent_panel_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(agent_panel_, 12);
    gtk_widget_set_margin_end(agent_panel_, 12);
    gtk_widget_set_margin_top(agent_panel_, 8);
    gtk_widget_set_margin_bottom(agent_panel_, 12);

    GtkWidget* agent_label = gtk_label_new("Ask the Agent:");
    gtk_label_set_xalign(GTK_LABEL(agent_label), 0.0);
    gtk_widget_add_css_class(agent_label, "heading");
    gtk_box_append(GTK_BOX(agent_panel_), agent_label);

    query_entry_ = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(query_entry_),
                                    "Ask about findings, correlations, or request further investigation...");
    g_signal_connect(query_entry_, "activate", G_CALLBACK(on_query_submitted), this);
    gtk_box_append(GTK_BOX(agent_panel_), query_entry_);

    agent_response_ = gtk_label_new("");
    gtk_label_set_wrap(GTK_LABEL(agent_response_), TRUE);
    gtk_label_set_xalign(GTK_LABEL(agent_response_), 0.0);
    gtk_widget_set_size_request(agent_response_, -1, 100);
    gtk_box_append(GTK_BOX(agent_panel_), agent_response_);
}

void DashboardWindow::on_open_clicked(GtkButton* /*button*/, gpointer user_data) {
    auto* self = static_cast<DashboardWindow*>(user_data);

    GtkFileDialog* file_dialog = gtk_file_dialog_new();
    GtkFileFilter* filter = gtk_file_filter_new();
    gtk_file_filter_add_pattern(filter, "*.json");
    gtk_file_filter_set_name(filter, "JSON Reports");

    GListStore* filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
    g_list_store_append(filters, filter);

    gtk_file_dialog_set_filters(file_dialog, G_LIST_MODEL(filters));
    gtk_file_dialog_set_title(file_dialog, "Open Report");

    gtk_file_dialog_open(file_dialog, GTK_WINDOW(self->window_), nullptr,
        +[](GObject* source, GAsyncResult* result, gpointer user_data) {
            auto* self = static_cast<DashboardWindow*>(user_data);
            GtkFileDialog* dialog = GTK_FILE_DIALOG(source);

            GFile* file = gtk_file_dialog_open_finish(dialog, result, nullptr);
            if (file) {
                char* path = g_file_get_path(file);
                if (path) {
                    self->load_report(path);
                    g_free(path);
                }
                g_object_unref(file);
            }
            g_object_unref(dialog);
        }, self);
}

void DashboardWindow::on_filter_changed(GtkSearchEntry* entry, gpointer user_data) {
    auto* self = static_cast<DashboardWindow*>(user_data);
    std::string search_text = gtk_editable_get_text(GTK_EDITABLE(entry));

    guint selected = gtk_drop_down_get_selected(GTK_DROP_DOWN(self->severity_dropdown_));
    const char* severities[] = {"", "critical", "high", "medium", "low", "info"};
    std::string severity = (selected < 6) ? severities[selected] : "";

    self->filter_findings(search_text, severity);
}

void DashboardWindow::on_severity_filter_changed(GObject* gobject, GParamSpec* /*pspec*/, gpointer user_data) {
    auto* dashboard = static_cast<DashboardWindow*>(user_data);
    std::string search_text = gtk_editable_get_text(GTK_EDITABLE(dashboard->search_entry_));

    GtkDropDown* dropdown = GTK_DROP_DOWN(gobject);
    guint selected = gtk_drop_down_get_selected(dropdown);
    const char* severities[] = {"", "critical", "high", "medium", "low", "info"};
    std::string severity = (selected < 6) ? severities[selected] : "";

    dashboard->filter_findings(search_text, severity);
}

void DashboardWindow::on_query_submitted(GtkEntry* entry, gpointer user_data) {
    auto* self = static_cast<DashboardWindow*>(user_data);
    std::string query = gtk_editable_get_text(GTK_EDITABLE(entry));
    self->submit_agent_query(query);
}

void DashboardWindow::on_start_interactive_analysis_clicked(GtkButton* /*button*/, gpointer user_data) {
    auto* self = static_cast<DashboardWindow*>(user_data);
    self->start_interactive_analysis();
}

void DashboardWindow::load_report(const std::string& report_path) {
    ReportParser parser;
    auto report_opt = parser.parse_file(report_path);

    if (!report_opt) {
        GtkAlertDialog* error_dialog = gtk_alert_dialog_new("Failed to load report: %s", report_path.c_str());
        gtk_alert_dialog_show(error_dialog, GTK_WINDOW(window_));
        return;
    }

    current_report_ = std::make_unique<Report>(std::move(*report_opt));
    current_report_path_ = report_path;
    populate_findings();

    std::string title = "sys-scan Security Dashboard - " + current_report_->hostname;
    gtk_window_set_title(GTK_WINDOW(window_), title.c_str());
}

void DashboardWindow::populate_findings() {
    if (!current_report_) return;

    // Clear existing list
    GtkWidget* scrolled = finding_list_;
    GtkWidget* old_child = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scrolled));
    if (old_child) {
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), nullptr);
    }

    GtkWidget* list_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    filtered_findings_ = current_report_->findings;

    for (size_t i = 0; i < filtered_findings_.size(); ++i) {
        GtkWidget* row = FindingView::create_finding_row(filtered_findings_[i]);
        GtkWidget* button = gtk_button_new();
        gtk_button_set_child(GTK_BUTTON(button), row);
        gtk_widget_add_css_class(button, "flat");

        auto* finding_data = new std::pair<DashboardWindow*, size_t>(this, i);
        g_signal_connect_swapped(button, "clicked", (GCallback)(+[](gpointer user_data) {
            auto* pair = static_cast<std::pair<DashboardWindow*, size_t>*>(user_data);
            if (pair && pair->first && pair->second < pair->first->filtered_findings_.size()) {
                pair->first->display_finding_details(pair->first->filtered_findings_[pair->second]);
            }
            delete pair;
        }), finding_data);

        gtk_box_append(GTK_BOX(list_box), button);
    }

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), list_box);
}

void DashboardWindow::filter_findings(const std::string& search_text, const std::string& severity) {
    if (!current_report_) return;

    filtered_findings_.clear();

    for (const auto& finding : current_report_->findings) {
        bool matches = true;

        if (!severity.empty() && finding.severity != severity) {
            matches = false;
        }

        if (!search_text.empty()) {
            std::string lower_search = search_text;
            std::string lower_title = finding.title;
            std::string lower_desc = finding.description;

            std::transform(lower_search.begin(), lower_search.end(), lower_search.begin(), ::tolower);
            std::transform(lower_title.begin(), lower_title.end(), lower_title.begin(), ::tolower);
            std::transform(lower_desc.begin(), lower_desc.end(), lower_desc.begin(), ::tolower);

            if (lower_title.find(lower_search) == std::string::npos &&
                lower_desc.find(lower_search) == std::string::npos) {
                matches = false;
            }
        }

        if (matches) {
            filtered_findings_.push_back(finding);
        }
    }

    populate_findings();
}

void DashboardWindow::display_finding_details(const Finding& finding) {
    // Clear old detail view
    GtkWidget* old_child = gtk_widget_get_first_child(detail_view_);
    while (old_child) {
        gtk_box_remove(GTK_BOX(detail_view_), old_child);
        old_child = gtk_widget_get_first_child(detail_view_);
    }

    GtkWidget* detail_widget = FindingView::create_detail_view(finding);
    gtk_box_append(GTK_BOX(detail_view_), detail_widget);
}

void DashboardWindow::submit_agent_query(const std::string& query) {
    if (!agent_->is_available()) {
        gtk_label_set_text(GTK_LABEL(agent_response_),
                          "Agent not available. Please install sys-scan-graph.");
        return;
    }

    gtk_label_set_text(GTK_LABEL(agent_response_), "Processing query...");

    // TODO: Get actual report path from loaded report
    std::string report_path = "/tmp/current_report.json";

    agent_->query_async(query, report_path, [this](const std::string& response) {
        g_idle_add(+[](gpointer user_data) -> gboolean {
            auto* pair = static_cast<std::pair<DashboardWindow*, std::string>*>(user_data);
            gtk_label_set_text(GTK_LABEL(pair->first->agent_response_), pair->second.c_str());
            delete pair;
            return G_SOURCE_REMOVE;
        }, new std::pair<DashboardWindow*, std::string>(this, response));
    });
}

void DashboardWindow::load_default_report() {
    // Try to load enriched_report.json from current directory
    std::string json_path = "enriched_report.json";
    if (std::filesystem::exists(json_path)) {
        load_report(json_path);
        return;
    }

    // Try to load enriched_report.json from reports subdirectory
    std::string reports_json_path = "reports/enriched_report.json";
    if (std::filesystem::exists(reports_json_path)) {
        load_report(reports_json_path);
        return;
    }

    // Try to load enriched_report.json from ../reports subdirectory (when running from build/)
    std::string build_reports_json_path = "../reports/enriched_report.json";
    if (std::filesystem::exists(build_reports_json_path)) {
        load_report(build_reports_json_path);
        return;
    }

    // Try to load enriched_report.json from parent directory (useful when running from build/)
    std::string parent_json_path = "../enriched_report.json";
    if (std::filesystem::exists(parent_json_path)) {
        load_report(parent_json_path);
        return;
    }

    // Try to load enriched_report.html from reports subdirectory
    std::string reports_html_path = "reports/enriched_report.html";
    if (std::filesystem::exists(reports_html_path)) {
        // For now, show a message that HTML loading is not supported
        GtkAlertDialog* info_dialog = gtk_alert_dialog_new("HTML reports are not yet supported. Please use JSON format.");
        gtk_alert_dialog_show(info_dialog, GTK_WINDOW(window_));
        return;
    }

    // No default report found - user will need to manually open one
}

void DashboardWindow::start_interactive_analysis() {
    if (!current_report_) {
        GtkAlertDialog* error_dialog = gtk_alert_dialog_new("Please load a report first before starting interactive analysis.");
        gtk_alert_dialog_show(error_dialog, GTK_WINDOW(window_));
        return;
    }

    // Launch Python interactive analysis script in background
    std::string python_cmd = "cd ../integration && python3 run_interactive_analysis.py";
    if (!current_report_path_.empty()) {
        python_cmd += " --report \"" + current_report_path_ + "\"";
    }

    // Start the Python process in background
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execl("/bin/sh", "sh", "-c", python_cmd.c_str(), nullptr);
        _exit(1); // If execl fails
    } else if (pid > 0) {
        // Parent process - start polling for IPC messages
        g_timeout_add(1000, [](gpointer user_data) -> gboolean {
            auto* self = static_cast<DashboardWindow*>(user_data);
            self->feedback_panel_->poll_feedback_requests();
            return G_SOURCE_CONTINUE;
        }, this);

        // Show status message
        gtk_label_set_text(GTK_LABEL(agent_response_), "Interactive analysis started. The agent may request your input.");
    } else {
        GtkAlertDialog* error_dialog = gtk_alert_dialog_new("Failed to start interactive analysis.");
        gtk_alert_dialog_show(error_dialog, GTK_WINDOW(window_));
    }
}

} // namespace SysScanUI
