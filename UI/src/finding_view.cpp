#include "finding_view.h"
#include <sstream>
#include <cmath>

namespace SysScanUI {

const char* FindingView::get_severity_color(const std::string& severity) {
    if (severity == "critical") return "#dc2626";
    if (severity == "high") return "#ea580c";
    if (severity == "medium") return "#d97706";
    if (severity == "low") return "#65a30d";
    return "#6b7280"; // info/default
}

const char* FindingView::get_severity_icon(const std::string& severity) {
    if (severity == "critical") return "⛔";
    if (severity == "high") return "🔴";
    if (severity == "medium") return "🟡";
    if (severity == "low") return "🟢";
    return "ℹ️"; // info/default
}

GtkWidget* FindingView::create_finding_row(const Finding& finding) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 8);

    // Severity icon
    GtkWidget* severity_label = gtk_label_new(get_severity_icon(finding.severity));
    gtk_widget_set_size_request(severity_label, 30, -1);
    gtk_box_append(GTK_BOX(box), severity_label);

    // Title and metadata
    GtkWidget* content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

    GtkWidget* title_label = gtk_label_new(finding.title.c_str());
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0);
    gtk_label_set_wrap(GTK_LABEL(title_label), TRUE);
    gtk_widget_add_css_class(title_label, "heading");
    gtk_box_append(GTK_BOX(content_box), title_label);

    std::ostringstream info;
    std::string risk_str = std::isfinite(finding.risk_total) ? std::to_string(finding.risk_total) : "N/A";
    info << "Risk: " << risk_str << " | ID: " << finding.id;
    GtkWidget* info_label = gtk_label_new(info.str().c_str());
    gtk_label_set_xalign(GTK_LABEL(info_label), 0.0);
    gtk_widget_add_css_class(info_label, "dim-label");
    gtk_box_append(GTK_BOX(content_box), info_label);

    gtk_box_append(GTK_BOX(box), content_box);
    gtk_widget_set_hexpand(content_box, TRUE);

    return box;
}

GtkWidget* FindingView::create_detail_view(const Finding& finding) {
    GtkWidget* scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                    GTK_POLICY_AUTOMATIC,
                                    GTK_POLICY_AUTOMATIC);

    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);
    gtk_widget_set_margin_start(box, 20);
    gtk_widget_set_margin_end(box, 20);
    gtk_widget_set_margin_top(box, 20);
    gtk_widget_set_margin_bottom(box, 20);

    // Title
    GtkWidget* title = gtk_label_new(finding.title.c_str());
    gtk_label_set_wrap(GTK_LABEL(title), TRUE);
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_add_css_class(title, "title-1");
    gtk_box_append(GTK_BOX(box), title);

    // Severity badge
    std::string severity_text = std::string(get_severity_icon(finding.severity)) + " " + finding.severity;
    GtkWidget* severity_badge = gtk_label_new(severity_text.c_str());
    gtk_label_set_xalign(GTK_LABEL(severity_badge), 0.0);
    gtk_widget_add_css_class(severity_badge, "badge");
    gtk_box_append(GTK_BOX(box), severity_badge);

    // Description
    if (!finding.description.empty()) {
        GtkWidget* desc_heading = gtk_label_new("Description");
        gtk_label_set_xalign(GTK_LABEL(desc_heading), 0.0);
        gtk_widget_add_css_class(desc_heading, "heading");
        gtk_box_append(GTK_BOX(box), desc_heading);

        GtkWidget* desc = gtk_label_new(finding.description.c_str());
        gtk_label_set_wrap(GTK_LABEL(desc), TRUE);
        gtk_label_set_xalign(GTK_LABEL(desc), 0.0);
        gtk_box_append(GTK_BOX(box), desc);
    }

    // Risk scores
    GtkWidget* risk_heading = gtk_label_new("Risk Assessment");
    gtk_label_set_xalign(GTK_LABEL(risk_heading), 0.0);
    gtk_widget_add_css_class(risk_heading, "heading");
    gtk_box_append(GTK_BOX(box), risk_heading);

    std::ostringstream risk_info;
    std::string risk_score_str = std::isfinite(finding.risk_score) ? std::to_string(finding.risk_score) : "N/A";
    std::string risk_total_str = std::isfinite(finding.risk_total) ? std::to_string(finding.risk_total) : "N/A";
    std::string prob_str = std::isfinite(finding.probability_actionable) ? std::to_string(finding.probability_actionable) : "N/A";
    risk_info << "Risk Score: " << risk_score_str << "\n"
              << "Total Risk: " << risk_total_str << "\n"
              << "Probability Actionable: " << prob_str << "\n"
              << "Baseline Status: " << finding.baseline_status;

    GtkWidget* risk_label = gtk_label_new(risk_info.str().c_str());
    gtk_label_set_xalign(GTK_LABEL(risk_label), 0.0);
    gtk_label_set_wrap(GTK_LABEL(risk_label), TRUE);
    gtk_box_append(GTK_BOX(box), risk_label);

    // Rationale
    if (!finding.rationale.empty()) {
        GtkWidget* rationale_heading = gtk_label_new("Analysis Rationale");
        gtk_label_set_xalign(GTK_LABEL(rationale_heading), 0.0);
        gtk_widget_add_css_class(rationale_heading, "heading");
        gtk_box_append(GTK_BOX(box), rationale_heading);

        for (const auto& reason : finding.rationale) {
            GtkWidget* reason_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
            GtkWidget* bullet = gtk_label_new("•");
            gtk_box_append(GTK_BOX(reason_box), bullet);

            GtkWidget* reason_label = gtk_label_new(reason.c_str());
            gtk_label_set_wrap(GTK_LABEL(reason_label), TRUE);
            gtk_label_set_xalign(GTK_LABEL(reason_label), 0.0);
            gtk_widget_set_hexpand(reason_label, TRUE);
            gtk_box_append(GTK_BOX(reason_box), reason_label);

            gtk_box_append(GTK_BOX(box), reason_box);
        }
    }

    // Tags
    if (!finding.tags.empty()) {
        GtkWidget* tags_heading = gtk_label_new("Tags");
        gtk_label_set_xalign(GTK_LABEL(tags_heading), 0.0);
        gtk_widget_add_css_class(tags_heading, "heading");
        gtk_box_append(GTK_BOX(box), tags_heading);

        GtkWidget* tags_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        for (const auto& tag : finding.tags) {
            GtkWidget* tag_label = gtk_label_new(tag.c_str());
            gtk_widget_add_css_class(tag_label, "badge");
            gtk_box_append(GTK_BOX(tags_box), tag_label);
        }
        gtk_box_append(GTK_BOX(box), tags_box);
    }

    // Metadata
    if (!finding.metadata.empty()) {
        GtkWidget* meta_heading = gtk_label_new("Metadata");
        gtk_label_set_xalign(GTK_LABEL(meta_heading), 0.0);
        gtk_widget_add_css_class(meta_heading, "heading");
        gtk_box_append(GTK_BOX(box), meta_heading);

        for (const auto& [key, value] : finding.metadata) {
            std::string meta_text = key + ": " + value;
            GtkWidget* meta_label = gtk_label_new(meta_text.c_str());
            gtk_label_set_xalign(GTK_LABEL(meta_label), 0.0);
            gtk_widget_add_css_class(meta_label, "monospace");
            gtk_box_append(GTK_BOX(box), meta_label);
        }
    }

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), box);
    return scrolled;
}

GtkWidget* FindingView::create_summary_card(const Summary& summary) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);
    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_bottom(box, 16);

    GtkWidget* title = gtk_label_new("Executive Summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_add_css_class(title, "title-2");
    gtk_box_append(GTK_BOX(box), title);

    if (!summary.executive_summary.empty()) {
        GtkWidget* summary_text = gtk_label_new(summary.executive_summary.c_str());
        gtk_label_set_wrap(GTK_LABEL(summary_text), TRUE);
        gtk_label_set_xalign(GTK_LABEL(summary_text), 0.0);
        gtk_box_append(GTK_BOX(box), summary_text);
    }

    // Severity counts
    if (!summary.severity_counts.empty()) {
        GtkWidget* severity_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
        gtk_widget_set_margin_top(severity_box, 12);

        for (const auto& [severity, count] : summary.severity_counts) {
            GtkWidget* count_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

            std::string count_text = std::to_string(count);
            GtkWidget* count_label = gtk_label_new(count_text.c_str());
            gtk_widget_add_css_class(count_label, "title-1");
            gtk_box_append(GTK_BOX(count_box), count_label);

            GtkWidget* sev_label = gtk_label_new(severity.c_str());
            gtk_widget_add_css_class(sev_label, "caption");
            gtk_box_append(GTK_BOX(count_box), sev_label);

            gtk_box_append(GTK_BOX(severity_box), count_box);
        }

        gtk_box_append(GTK_BOX(box), severity_box);
    }

    return box;
}

GtkWidget* FindingView::create_correlation_view(const Correlation& correlation) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 8);

    GtkWidget* title = gtk_label_new(correlation.title.c_str());
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_add_css_class(title, "heading");
    gtk_box_append(GTK_BOX(box), title);

    if (!correlation.rationale.empty()) {
        GtkWidget* rationale = gtk_label_new(correlation.rationale.c_str());
        gtk_label_set_wrap(GTK_LABEL(rationale), TRUE);
        gtk_label_set_xalign(GTK_LABEL(rationale), 0.0);
        gtk_box_append(GTK_BOX(box), rationale);
    }

    std::ostringstream info;
    info << "Related findings: " << correlation.related_finding_ids.size();
    GtkWidget* info_label = gtk_label_new(info.str().c_str());
    gtk_label_set_xalign(GTK_LABEL(info_label), 0.0);
    gtk_widget_add_css_class(info_label, "dim-label");
    gtk_box_append(GTK_BOX(box), info_label);

    return box;
}

} // namespace SysScanUI
