module;
#include <thread>
#include <future>
#include <chrono>
#include <vector>
#include <QString>

// llama includes are resolved when FetchContent makes llama available
#include <llama.h>

module sys_scan.ui.agent;

import sys_scan.ui.coro;

namespace sys_scan::ui {

    struct AgentService::Impl {
        llama_model* model = nullptr;
        llama_context* ctx = nullptr;
    };

    AgentService::AgentService(QObject* parent)
        : QObject(parent), m_impl(new Impl()) {}

    AgentService::~AgentService() {
        if (m_impl) {
            if (m_impl->ctx) llama_free(m_impl->ctx);
            if (m_impl->model) llama_free_model(m_impl->model);
            delete m_impl;
        }
    }

    bool AgentService::loadModel(const QString& modelPath) {
        // Guard: if llama isn't present, return false
#ifdef LLAMA_API_VERSION
        llama_model_params model_params = llama_model_default_params();
        model_params.n_gpu_layers = 99; // prefer Vulkan offload

        m_impl->model = llama_load_model_from_file(modelPath.toStdString().c_str(), model_params);
        if (!m_impl->model) return false;

        llama_context_params ctx_params = llama_context_default_params();
        ctx_params.n_ctx = 2048;
        m_impl->ctx = llama_new_context_with_model(m_impl->model, ctx_params);
        return (m_impl->ctx != nullptr);
#else
        Q_UNUSED(modelPath);
        return false;
#endif
    }

    void AgentService::promptAsync(const QString& prompt) {
        std::thread([this, p = prompt.toStdString()]() {
            for (auto token : this->ask(p)) {
                QMetaObject::invokeMethod(this, [this, t = token]() {
                    emit tokenReceived(t);
                });
            }
            QMetaObject::invokeMethod(this, [this]() {
                emit generationFinished();
            });
        }).detach();
    }

    Generator<QString> AgentService::ask(std::string prompt) {
        // Mock streaming if model not loaded
        if (!m_impl || !m_impl->model) {
            std::vector<std::string> mock = {"Ana", "lyz", "ing", " sys", "tem", " sec", "ur", "ity", "..."};
            for (const auto& t : mock) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                co_yield QString::fromStdString(t);
            }
            co_return;
        }

        // Real Llama streaming would be implemented here by tokenizing the prompt,
        // calling llama_eval and llama_sample_token in a loop and co_yield-ing tokens.
        co_return;
    }

}

// Place moc compile into a private module fragment so vtable and metaobject are emitted here
module :private;
#include "agent_service.moc"
