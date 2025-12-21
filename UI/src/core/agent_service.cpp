module;
#include <thread>
#include <future>
#include <chrono>
#include <vector>
#include <QString>
#include <string>
#include <coroutine>

// llama includes are resolved when FetchContent makes llama available
#include <llama.h>

module sys_scan.ui.agent;

import sys_scan.ui.coro;

namespace sys_scan::ui {

    struct AgentService::Impl {
        llama_model* model = nullptr;
        llama_context* ctx = nullptr;
        llama_sampler* sampler = nullptr; // sampler chain for token sampling
    };

    AgentService::AgentService(QObject* parent)
        : QObject(parent), m_impl(new Impl()) {
            llama_backend_init(); // Initialize backend once
    }

    AgentService::~AgentService() {
        if (m_impl) {
            if (m_impl->sampler) llama_sampler_free(m_impl->sampler);
            if (m_impl->ctx) llama_free(m_impl->ctx);
            if (m_impl->model) llama_free_model(m_impl->model);
            delete m_impl;
        }
        // llama_backend_free(); // Optional depending on app lifecycle
    }

    bool AgentService::loadModel(const QString& modelPath) {
#ifdef LLAMA_API_VERSION
        // Cleanup previous resources
        if (m_impl->sampler) { llama_sampler_free(m_impl->sampler); m_impl->sampler = nullptr; }
        if (m_impl->ctx) { llama_free(m_impl->ctx); m_impl->ctx = nullptr; }
        if (m_impl->model) { llama_free_model(m_impl->model); m_impl->model = nullptr; }

        llama_model_params model_params = llama_model_default_params();
        model_params.n_gpu_layers = 99; // Attempt to offload all layers to GPU

        m_impl->model = llama_load_model_from_file(modelPath.toStdString().c_str(), model_params);
        if (!m_impl->model) return false;

        llama_context_params ctx_params = llama_context_default_params();
        ctx_params.n_ctx = 2048;
        ctx_params.n_batch = 512;
        
        m_impl->ctx = llama_new_context_with_model(m_impl->model, ctx_params);
        
        if (m_impl->ctx) {
            // Initialize sampler chain: Greedy -> TopK -> TopP
            m_impl->sampler = llama_sampler_chain_init(llama_sampler_chain_default_params());
            llama_sampler_chain_add(m_impl->sampler, llama_sampler_init_temp(0.8f));
            llama_sampler_chain_add(m_impl->sampler, llama_sampler_init_top_k(40));
            llama_sampler_chain_add(m_impl->sampler, llama_sampler_init_top_p(0.95f, 1));
            llama_sampler_chain_add(m_impl->sampler, llama_sampler_init_dist(1234)); // Fixed seed for reproducibility
        }

        return (m_impl->ctx != nullptr);
#else
        Q_UNUSED(modelPath);
        return false;
#endif
    }

    void AgentService::promptAsync(const QString& prompt) {
        std::thread([this, p = prompt.toStdString()]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
#ifdef LLAMA_API_VERSION
        if (!m_impl || !m_impl->model || !m_impl->ctx) {
            co_yield "Error: Model not loaded.";
            co_return;
        }

        // 1. Tokenize prompt
        const int n_ctx = llama_n_ctx(m_impl->ctx);
        std::vector<llama_token> tokens_list(n_ctx);
        int n_tokens = llama_tokenize(m_impl->model, prompt.c_str(), (int)prompt.size(), tokens_list.data(), (int)tokens_list.size(), true, true);

        if (n_tokens < 0) {
            co_yield "Error: Prompt too long.";
            co_return;
        }
        tokens_list.resize(n_tokens);

        // Prepare an evaluation batch
        llama_batch batch = llama_batch_init(512, 0, 1);

        for (int i = 0; i < n_tokens; ++i) {
            llama_batch_add(batch, tokens_list[i], i, { 0 }, i == n_tokens - 1);
        }

        if (llama_decode(m_impl->ctx, batch) != 0) {
            co_yield "Error: Decode failed.";
            llama_batch_free(batch);
            co_return;
        }

        // Generator loop: sample tokens and yield pieces
        int n_decode = 0;
        const int max_gen = 512;

        while (n_decode < max_gen) {
            // Use sampler if available
            llama_token new_token = 0;
            if (m_impl->sampler) {
                new_token = llama_sampler_sample(reinterpret_cast<llama_sampler*>(m_impl->sampler), m_impl->ctx, -1);
            } else {
                // Fallback to basic sampling API if sampler not present
                new_token = llama_sample_token(m_impl->model, m_impl->ctx, -1);
            }

            if (llama_token_is_eog(m_impl->model, new_token)) {
                break;
            }

            char buf[512];
            int n = llama_token_to_piece(m_impl->model, new_token, buf, sizeof(buf), 0, true);
            if (n > 0) {
                std::string piece(buf, n);
                co_yield QString::fromStdString(piece);
            }

            llama_batch_clear(batch);
            llama_batch_add(batch, new_token, n_tokens + n_decode, { 0 }, true);
            if (llama_decode(m_impl->ctx, batch) != 0) break;
            ++n_decode;
        }

        llama_batch_free(batch);
        co_return;
#else
        // Legacy mock streaming if llama not available
        std::vector<std::string> mock = {"Ana", "lyz", "ing", " sys", "tem", " sec", "ur", "ity", "..."};
        for (const auto& t : mock) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            co_yield QString::fromStdString(t);
        }
        co_return;
#endif
    }

}

// moc generated in the interface unit (agent_service.ixx)
