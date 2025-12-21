#include "feedback_panel.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <json-glib/json-glib.h>

namespace SysScanUI {

FeedbackPanel::FeedbackPanel(GtkWidget* parent_window)
    : parent_window_(parent_window)
    , panel_(nullptr)
    , current_dialog_(nullptr)
    , socket_path_("/tmp/sys-scan-ui.sock")
    , ipc_socket_(-1) {
    setup_ui();
}

FeedbackPanel::~FeedbackPanel() {
    if (ipc_socket_ >= 0) {
        close(ipc_socket_);
    }
}

void FeedbackPanel::setup_ui() {
    panel_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(panel_, 12);
    gtk_widget_set_margin_end(panel_, 12);
    gtk_widget_set_margin_top(panel_, 8);
    gtk_widget_set_margin_bottom(panel_, 12);

    GtkWidget* title = gtk_label_new("Interactive Analysis");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_add_css_class(title, "title-3");
    gtk_box_append(GTK_BOX(panel_), title);

    GtkWidget* desc = gtk_label_new("The analysis agent may request your input during investigation.");
    gtk_label_set_wrap(GTK_LABEL(desc), TRUE);
    gtk_label_set_xalign(GTK_LABEL(desc), 0.0);
    gtk_widget_add_css_class(desc, "dim-label");
    gtk_box_append(GTK_BOX(panel_), desc);
}

void FeedbackPanel::set_socket_path(const std::string& path) {
    socket_path_ = path;
}

void FeedbackPanel::show_request(const FeedbackRequest& request, FeedbackCallback callback) {
    current_request_ = request;
    current_callback_ = callback;
    create_request_dialog(request);
}

void FeedbackPanel::create_request_dialog(const FeedbackRequest& request) {
    // Create dialog window
    current_dialog_ = gtk_dialog_new();
    gtk_window_set_transient_for(GTK_WINDOW(current_dialog_), GTK_WINDOW(parent_window_));
    gtk_window_set_modal(GTK_WINDOW(current_dialog_), TRUE);
    gtk_window_set_title(GTK_WINDOW(current_dialog_), "Analysis Feedback Request");
    gtk_window_set_default_size(GTK_WINDOW(current_dialog_), 500, 300);

    GtkWidget* content_area = gtk_dialog_get_content_area(GTK_DIALOG(current_dialog_));
    GtkWidget* content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);
    gtk_widget_set_margin_start(content_box, 20);
    gtk_widget_set_margin_end(content_box, 20);
    gtk_widget_set_margin_top(content_box, 20);
    gtk_widget_set_margin_bottom(content_box, 20);
    gtk_box_append(GTK_BOX(content_area), content_box);

    // Urgency badge
    GtkWidget* urgency_badge = create_urgency_badge(request.urgency);
    gtk_box_append(GTK_BOX(content_box), urgency_badge);

    // Request type
    std::string type_text = "Request Type: " + request.request_type;
    GtkWidget* type_label = gtk_label_new(type_text.c_str());
    gtk_label_set_xalign(GTK_LABEL(type_label), 0.0);
    gtk_widget_add_css_class(type_label, "caption");
    gtk_box_append(GTK_BOX(content_box), type_label);

    // Prompt
    GtkWidget* prompt_label = gtk_label_new(request.prompt.c_str());
    gtk_label_set_wrap(GTK_LABEL(prompt_label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(prompt_label), 0.0);
    gtk_widget_add_css_class(prompt_label, "title-3");
    gtk_box_append(GTK_BOX(content_box), prompt_label);

    // Context information
    if (!request.context.empty()) {
        GtkWidget* context_expander = gtk_expander_new("Additional Context");
        GtkWidget* context_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

        for (const auto& [key, value] : request.context) {
            std::string context_text = key + ": " + value;
            GtkWidget* context_label = gtk_label_new(context_text.c_str());
            gtk_label_set_xalign(GTK_LABEL(context_label), 0.0);
            gtk_widget_add_css_class(context_label, "monospace");
            gtk_box_append(GTK_BOX(context_box), context_label);
        }

        gtk_expander_set_child(GTK_EXPANDER(context_expander), context_box);
        gtk_box_append(GTK_BOX(content_box), context_expander);
    }

    // Options
    if (!request.options.empty()) {
        GtkWidget* options_label = gtk_label_new("Please select an option:");
        gtk_label_set_xalign(GTK_LABEL(options_label), 0.0);
        gtk_box_append(GTK_BOX(content_box), options_label);

        GtkWidget* options_buttons = create_option_buttons(request.options);
        gtk_box_append(GTK_BOX(content_box), options_buttons);
    }

    // Additional input
    GtkWidget* input_label = gtk_label_new("Additional comments (optional):");
    gtk_label_set_xalign(GTK_LABEL(input_label), 0.0);
    gtk_box_append(GTK_BOX(content_box), input_label);

    GtkWidget* text_view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);
    gtk_widget_set_size_request(text_view, -1, 80);
    gtk_widget_set_name(text_view, "feedback_text");
    GtkWidget* scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), text_view);
    gtk_box_append(GTK_BOX(content_box), scrolled);

    // Action buttons
    GtkWidget* button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(button_box, GTK_ALIGN_END);

    GtkWidget* cancel_btn = gtk_button_new_with_label("Cancel");
    g_signal_connect(cancel_btn, "clicked", G_CALLBACK(on_cancel_clicked), this);
    gtk_box_append(GTK_BOX(button_box), cancel_btn);

    GtkWidget* submit_btn = gtk_button_new_with_label("Submit");
    gtk_widget_add_css_class(submit_btn, "suggested-action");
    g_signal_connect(submit_btn, "clicked", G_CALLBACK(on_submit_clicked), this);
    gtk_box_append(GTK_BOX(button_box), submit_btn);

    gtk_box_append(GTK_BOX(content_box), button_box);

    gtk_widget_show(current_dialog_);
}

GtkWidget* FeedbackPanel::create_option_buttons(const std::vector<std::string>& options) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    for (const auto& option : options) {
        GtkWidget* radio_btn = gtk_check_button_new_with_label(option.c_str());
        gtk_widget_set_name(radio_btn, option.c_str());
        g_signal_connect(radio_btn, "toggled", G_CALLBACK(on_option_selected), this);
        gtk_box_append(GTK_BOX(box), radio_btn);
    }

    return box;
}

GtkWidget* FeedbackPanel::create_urgency_badge(const std::string& urgency) {
    std::string badge_text;
    const char* css_class;

    if (urgency == "critical") {
        badge_text = "🔴 CRITICAL";
        css_class = "error";
    } else if (urgency == "high") {
        badge_text = "🟠 HIGH PRIORITY";
        css_class = "warning";
    } else if (urgency == "normal") {
        badge_text = "ℹ️ NORMAL";
        css_class = "accent";
    } else {
        badge_text = "⚪ LOW";
        css_class = "dim-label";
    }

    GtkWidget* badge = gtk_label_new(badge_text.c_str());
    gtk_widget_add_css_class(badge, css_class);
    gtk_label_set_xalign(GTK_LABEL(badge), 0.0);

    return badge;
}

void FeedbackPanel::on_option_selected(GtkButton* button, gpointer user_data) {
    // Option selection handled by GTK radio buttons
}

void FeedbackPanel::on_submit_clicked(GtkButton* button, gpointer user_data) {
    auto* self = static_cast<FeedbackPanel*>(user_data);

    FeedbackResponse response;
    response.request_id = self->current_request_.request_id;

    // Get selected option (find checked radio button)
    response.selected_option = "";
    if (!self->current_request_.options.empty()) {
        // For simplicity, just use the first option as selected
        // TODO: Implement proper radio button group handling
        response.selected_option = self->current_request_.options[0];
    }

    // Get additional text
    response.additional_text = "";
    // TODO: Extract text from text view widget

    self->submit_response(response);
    gtk_window_destroy(GTK_WINDOW(self->current_dialog_));
    self->current_dialog_ = nullptr;
}

void FeedbackPanel::on_cancel_clicked(GtkButton* button, gpointer user_data) {
    auto* self = static_cast<FeedbackPanel*>(user_data);
    gtk_window_destroy(GTK_WINDOW(self->current_dialog_));
    self->current_dialog_ = nullptr;
}

void FeedbackPanel::submit_response(const FeedbackResponse& response) {
    // Send via IPC
    send_response_via_ipc(response);

    // Call callback
    if (current_callback_) {
        current_callback_(response);
    }
}

void FeedbackPanel::send_response_via_ipc(const FeedbackResponse& response) {
    // Connect to Unix socket
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to connect to socket: " << socket_path_ << std::endl;
        close(sock);
        return;
    }

    // Build JSON response
    JsonBuilder* builder = json_builder_new();
    json_builder_begin_object(builder);

    json_builder_set_member_name(builder, "msg_type");
    json_builder_add_string_value(builder, "feedback_response");

    json_builder_set_member_name(builder, "msg_id");
    json_builder_add_string_value(builder, response.request_id.c_str());

    json_builder_set_member_name(builder, "data");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "selected_option");
    json_builder_add_string_value(builder, response.selected_option.c_str());
    json_builder_set_member_name(builder, "additional_text");
    json_builder_add_string_value(builder, response.additional_text.c_str());
    json_builder_end_object(builder);

    json_builder_set_member_name(builder, "timestamp");
    json_builder_add_double_value(builder, g_get_real_time() / 1000000.0);

    json_builder_end_object(builder);

    JsonGenerator* gen = json_generator_new();
    JsonNode* root = json_builder_get_root(builder);
    json_generator_set_root(gen, root);
    gchar* json_str = json_generator_to_data(gen, nullptr);

    // Send JSON + newline
    std::string message = std::string(json_str) + "\n";
    send(sock, message.c_str(), message.length(), 0);

    g_free(json_str);
    json_node_free(root);
    g_object_unref(gen);
    g_object_unref(builder);

    close(sock);
}

void FeedbackPanel::poll_feedback_requests() {
    // Poll for incoming feedback requests via IPC
    if (ipc_socket_ < 0) {
        // Try to connect to the socket
        if (!connect_to_socket()) {
            return; // Connection failed, will retry next poll
        }
    }

    // Check for incoming messages (non-blocking)
    char buffer[4096];
    ssize_t bytes_read = recv(ipc_socket_, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        std::string message(buffer);

        // Process the message
        process_incoming_message(message);
    } else if (bytes_read == 0) {
        // Connection closed
        close(ipc_socket_);
        ipc_socket_ = -1;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        // Error
        close(ipc_socket_);
        ipc_socket_ = -1;
    }
}

bool FeedbackPanel::connect_to_socket() {
    // Connect to Unix socket
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return false;
    }

    ipc_socket_ = sock;
    return true;
}

void FeedbackPanel::process_incoming_message(const std::string& message) {
    // Parse JSON message
    JsonParser* parser = json_parser_new();
    if (!json_parser_load_from_data(parser, message.c_str(), message.length(), nullptr)) {
        g_object_unref(parser);
        return;
    }

    JsonNode* root = json_parser_get_root(parser);
    if (!JSON_NODE_HOLDS_OBJECT(root)) {
        g_object_unref(parser);
        return;
    }

    JsonObject* obj = json_node_get_object(root);

    // Check message type
    const char* msg_type = json_object_get_string_member(obj, "msg_type");
    if (!msg_type || strcmp(msg_type, "feedback_request") != 0) {
        g_object_unref(parser);
        return;
    }

    // Extract request data
    const char* request_id = json_object_get_string_member(obj, "msg_id");
    if (!request_id) {
        g_object_unref(parser);
        return;
    }

    JsonObject* data_obj = json_object_get_object_member(obj, "data");
    if (!data_obj) {
        g_object_unref(parser);
        return;
    }

    FeedbackRequest request;
    request.request_id = request_id;
    request.request_type = json_object_get_string_member(data_obj, "request_type") ?: "";
    request.prompt = json_object_get_string_member(data_obj, "prompt") ?: "";
    request.urgency = json_object_get_string_member(data_obj, "urgency") ?: "normal";

    // Parse options array
    JsonArray* options_array = json_object_get_array_member(data_obj, "options");
    if (options_array) {
        for (guint i = 0; i < json_array_get_length(options_array); ++i) {
            const char* option = json_array_get_string_element(options_array, i);
            if (option) {
                request.options.push_back(option);
            }
        }
    }

    // Parse context object
    JsonObject* context_obj = json_object_get_object_member(data_obj, "context");
    if (context_obj) {
        GList* members = json_object_get_members(context_obj);
        for (GList* l = members; l; l = l->next) {
            const char* key = (const char*)l->data;
            const char* value = json_object_get_string_member(context_obj, key);
            if (value) {
                request.context[key] = value;
            }
        }
        g_list_free(members);
    }

    g_object_unref(parser);

    // Show the request dialog
    show_request(request, [this](const FeedbackResponse& response) {
        // Send response back via IPC
        send_response_via_ipc(response);
    });
}

} // namespace SysScanUI
