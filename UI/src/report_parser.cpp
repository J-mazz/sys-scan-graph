#include "report_parser.h"
#include <fstream>
#include <sstream>
#include <iostream>

namespace SysScanUI {

std::optional<Report> ReportParser::parse_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << file_path << std::endl;
        return std::nullopt;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return parse_json(buffer.str());
}

std::optional<Report> ReportParser::parse_json(const std::string& json_str) {
    GError* error = nullptr;
    JsonParser* parser = json_parser_new();

    if (!json_parser_load_from_data(parser, json_str.c_str(), -1, &error)) {
        std::cerr << "JSON parse error: " << error->message << std::endl;
        g_error_free(error);
        g_object_unref(parser);
        return std::nullopt;
    }

    JsonNode* root = json_parser_get_root(parser);
    if (!JSON_NODE_HOLDS_OBJECT(root)) {
        g_object_unref(parser);
        return std::nullopt;
    }

    JsonObject* root_obj = json_node_get_object(root);
    Report report;

    // Parse metadata
    if (json_object_has_member(root_obj, "meta")) {
        JsonObject* meta = json_object_get_object_member(root_obj, "meta");
        if (json_object_has_member(meta, "hostname")) {
            report.hostname = json_object_get_string_member(meta, "hostname");
        }
        if (json_object_has_member(meta, "tool_version")) {
            report.tool_version = json_object_get_string_member(meta, "tool_version");
        }
    }

    // Parse enriched findings (preferred) or findings (fallback)
    if (json_object_has_member(root_obj, "enriched_findings")) {
        JsonNode* findings_node = json_object_get_member(root_obj, "enriched_findings");
        if (JSON_NODE_HOLDS_ARRAY(findings_node)) {
            JsonArray* findings_arr = json_node_get_array(findings_node);
            guint len = json_array_get_length(findings_arr);
            for (guint i = 0; i < len; i++) {
                JsonNode* finding_node = json_array_get_element(findings_arr, i);
                if (JSON_NODE_HOLDS_OBJECT(finding_node)) {
                    JsonObject* finding_obj = json_node_get_object(finding_node);
                    report.findings.push_back(parse_finding(finding_obj));
                }
            }
        }
    } else if (json_object_has_member(root_obj, "findings")) {
        JsonNode* findings_node = json_object_get_member(root_obj, "findings");
        if (JSON_NODE_HOLDS_ARRAY(findings_node)) {
            JsonArray* findings_arr = json_node_get_array(findings_node);
            guint len = json_array_get_length(findings_arr);
            for (guint i = 0; i < len; i++) {
                JsonNode* finding_node = json_array_get_element(findings_arr, i);
                if (JSON_NODE_HOLDS_OBJECT(finding_node)) {
                    JsonObject* finding_obj = json_node_get_object(finding_node);
                    report.findings.push_back(parse_finding(finding_obj));
                }
            }
        }
    }

    // Parse correlations
    if (json_object_has_member(root_obj, "correlations")) {
        JsonNode* corr_node = json_object_get_member(root_obj, "correlations");
        if (JSON_NODE_HOLDS_ARRAY(corr_node)) {
            JsonArray* corr_arr = json_node_get_array(corr_node);
            guint len = json_array_get_length(corr_arr);
            for (guint i = 0; i < len; i++) {
                JsonNode* corr_elem_node = json_array_get_element(corr_arr, i);
                if (JSON_NODE_HOLDS_OBJECT(corr_elem_node)) {
                    JsonObject* corr_obj = json_node_get_object(corr_elem_node);
                    report.correlations.push_back(parse_correlation(corr_obj));
                }
            }
        }
    }

    // Parse summaries (preferred) or summary (fallback)
    if (json_object_has_member(root_obj, "summaries")) {
        JsonNode* summaries_node = json_object_get_member(root_obj, "summaries");
        if (JSON_NODE_HOLDS_OBJECT(summaries_node)) {
            JsonObject* summaries = json_node_get_object(summaries_node);
            report.summary = parse_summary(summaries);
        }
    } else if (json_object_has_member(root_obj, "summary")) {
        JsonNode* summary_node = json_object_get_member(root_obj, "summary");
        if (JSON_NODE_HOLDS_OBJECT(summary_node)) {
            JsonObject* summary = json_node_get_object(summary_node);
            report.summary = parse_summary(summary);
        }
    }

    g_object_unref(parser);
    return report;
}

Finding ReportParser::parse_finding(JsonObject* obj) {
    Finding f;

    if (json_object_has_member(obj, "id")) {
        JsonNode* node = json_object_get_member(obj, "id");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                f.id = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "title")) {
        JsonNode* node = json_object_get_member(obj, "title");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                f.title = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "description")) {
        JsonNode* node = json_object_get_member(obj, "description");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                f.description = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "severity")) {
        JsonNode* node = json_object_get_member(obj, "severity");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                f.severity = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "category")) {
        JsonNode* node = json_object_get_member(obj, "category");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                f.category = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "baseline_status")) {
        JsonNode* node = json_object_get_member(obj, "baseline_status");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                f.baseline_status = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }

    if (json_object_has_member(obj, "risk_score")) {
        JsonNode* risk_node = json_object_get_member(obj, "risk_score");
        if (JSON_NODE_HOLDS_VALUE(risk_node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(risk_node, &value);
            if (G_VALUE_HOLDS_DOUBLE(&value)) {
                f.risk_score = g_value_get_double(&value);
            } else if (G_VALUE_HOLDS_INT64(&value)) {
                f.risk_score = static_cast<double>(g_value_get_int64(&value));
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "risk_total")) {
        JsonNode* risk_node = json_object_get_member(obj, "risk_total");
        if (JSON_NODE_HOLDS_VALUE(risk_node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(risk_node, &value);
            if (G_VALUE_HOLDS_DOUBLE(&value)) {
                f.risk_total = g_value_get_double(&value);
            } else if (G_VALUE_HOLDS_INT64(&value)) {
                f.risk_total = static_cast<double>(g_value_get_int64(&value));
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "probability_actionable")) {
        JsonNode* prob_node = json_object_get_member(obj, "probability_actionable");
        if (JSON_NODE_HOLDS_VALUE(prob_node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(prob_node, &value);
            if (G_VALUE_HOLDS_DOUBLE(&value)) {
                f.probability_actionable = g_value_get_double(&value);
            } else if (G_VALUE_HOLDS_INT64(&value)) {
                f.probability_actionable = static_cast<double>(g_value_get_int64(&value));
            }
            g_value_unset(&value);
        }
    }

    if (json_object_has_member(obj, "tags")) {
        JsonNode* tags_node = json_object_get_member(obj, "tags");
        if (JSON_NODE_HOLDS_ARRAY(tags_node)) {
            JsonArray* tags_arr = json_node_get_array(tags_node);
            f.tags = parse_string_array(tags_arr);
        }
    }

    if (json_object_has_member(obj, "rationale")) {
        JsonNode* rationale_node = json_object_get_member(obj, "rationale");
        if (JSON_NODE_HOLDS_ARRAY(rationale_node)) {
            JsonArray* rationale_arr = json_node_get_array(rationale_node);
            f.rationale = parse_string_array(rationale_arr);
        }
    }

    if (json_object_has_member(obj, "metadata")) {
        JsonNode* meta_node = json_object_get_member(obj, "metadata");
        if (JSON_NODE_HOLDS_OBJECT(meta_node)) {
            JsonObject* meta = json_node_get_object(meta_node);
            f.metadata = parse_metadata(meta);
        }
    }

    return f;
}

Correlation ReportParser::parse_correlation(JsonObject* obj) {
    Correlation c;

    if (json_object_has_member(obj, "id")) {
        JsonNode* node = json_object_get_member(obj, "id");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                c.id = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "title")) {
        JsonNode* node = json_object_get_member(obj, "title");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                c.title = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }
    if (json_object_has_member(obj, "rationale")) {
        JsonNode* node = json_object_get_member(obj, "rationale");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                c.rationale = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }

    if (json_object_has_member(obj, "tags")) {
        JsonNode* tags_node = json_object_get_member(obj, "tags");
        if (JSON_NODE_HOLDS_ARRAY(tags_node)) {
            JsonArray* tags_arr = json_node_get_array(tags_node);
            c.tags = parse_string_array(tags_arr);
        }
    }

    if (json_object_has_member(obj, "related_finding_ids")) {
        JsonNode* ids_node = json_object_get_member(obj, "related_finding_ids");
        if (JSON_NODE_HOLDS_ARRAY(ids_node)) {
            JsonArray* ids_arr = json_node_get_array(ids_node);
            c.related_finding_ids = parse_string_array(ids_arr);
        }
    }

    return c;
}

Summary ReportParser::parse_summary(JsonObject* obj) {
    Summary s;

    if (json_object_has_member(obj, "executive_summary")) {
        JsonNode* node = json_object_get_member(obj, "executive_summary");
        if (JSON_NODE_HOLDS_VALUE(node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(node, &value);
            if (G_VALUE_HOLDS_STRING(&value)) {
                s.executive_summary = g_value_get_string(&value);
            }
            g_value_unset(&value);
        }
    }

    if (json_object_has_member(obj, "finding_count_total")) {
        s.finding_count_total = json_object_get_int_member(obj, "finding_count_total");
    }

    if (json_object_has_member(obj, "finding_count_emitted")) {
        s.finding_count_emitted = json_object_get_int_member(obj, "finding_count_emitted");
    }

    if (json_object_has_member(obj, "severity_counts")) {
        JsonNode* severity_node = json_object_get_member(obj, "severity_counts");
        if (JSON_NODE_HOLDS_OBJECT(severity_node)) {
            JsonObject* severity_obj = json_node_get_object(severity_node);
            GList* members = json_object_get_members(severity_obj);
            for (GList* l = members; l != nullptr; l = l->next) {
                const char* key = static_cast<const char*>(l->data);
                int count = json_object_get_int_member(severity_obj, key);
                s.severity_counts[key] = count;
            }
            g_list_free(members);
        }
    }

    if (json_object_has_member(obj, "metrics")) {
        JsonNode* metrics_node = json_object_get_member(obj, "metrics");
        if (JSON_NODE_HOLDS_OBJECT(metrics_node)) {
            JsonObject* metrics = json_node_get_object(metrics_node);
            // Convert metrics to string map for display
            GList* members = json_object_get_members(metrics);
            for (GList* l = members; l != nullptr; l = l->next) {
                const char* key = static_cast<const char*>(l->data);
                JsonNode* value_node = json_object_get_member(metrics, key);

                if (JSON_NODE_HOLDS_VALUE(value_node)) {
                    GValue value = G_VALUE_INIT;
                    json_node_get_value(value_node, &value);

                    if (G_VALUE_HOLDS_STRING(&value)) {
                        s.metrics[key] = g_value_get_string(&value);
                    } else if (G_VALUE_HOLDS_INT64(&value)) {
                        s.metrics[key] = std::to_string(g_value_get_int64(&value));
                    } else if (G_VALUE_HOLDS_DOUBLE(&value)) {
                        s.metrics[key] = std::to_string(g_value_get_double(&value));
                    }

                    g_value_unset(&value);
                }
            }
            g_list_free(members);
        }
    }

    return s;
}

std::vector<std::string> ReportParser::parse_string_array(JsonArray* arr) {
    std::vector<std::string> result;
    if (!arr) return result;

    guint len = json_array_get_length(arr);
    for (guint i = 0; i < len; i++) {
        const char* str = json_array_get_string_element(arr, i);
        if (str) {
            result.push_back(str);
        }
    }
    return result;
}

std::map<std::string, std::string> ReportParser::parse_metadata(JsonObject* obj) {
    std::map<std::string, std::string> result;
    if (!obj) return result;

    GList* members = json_object_get_members(obj);
    for (GList* l = members; l != nullptr; l = l->next) {
        const char* key = static_cast<const char*>(l->data);
        JsonNode* value_node = json_object_get_member(obj, key);

        if (JSON_NODE_HOLDS_VALUE(value_node)) {
            GValue value = G_VALUE_INIT;
            json_node_get_value(value_node, &value);

            if (G_VALUE_HOLDS_STRING(&value)) {
                result[key] = g_value_get_string(&value);
            } else if (G_VALUE_HOLDS_INT64(&value)) {
                result[key] = std::to_string(g_value_get_int64(&value));
            } else if (G_VALUE_HOLDS_DOUBLE(&value)) {
                result[key] = std::to_string(g_value_get_double(&value));
            }

            g_value_unset(&value);
        }
    }
    g_list_free(members);

    return result;
}

} // namespace SysScanUI
