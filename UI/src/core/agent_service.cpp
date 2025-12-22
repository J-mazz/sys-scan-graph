#include "agent_service.h"
#include <thread>
#include <vector>
#include <string>
#include <coroutine>
#include <llama.h>

#include "coro.h"

// Define the PIMPL in the global fragment (match header's forward declaration)
struct sys_scan::ui::AgentServiceImpl {
    llama_model* model = nullptr;
    llama_context* ctx = nullptr;
    llama_sampler* sampler = nullptr;
};

import sys_scan.ui.coro;
sys_scan::ui::AgentService::AgentService(QObject* parent)
    : QObject(parent), m_impl(new sys_scan::ui::AgentServiceImpl()) {
        llama_backend_init();
}

sys_scan::ui::AgentService::~AgentService() {
    if (m_impl) {
        if (m_impl->sampler) llama_sampler_free(m_impl->sampler);
        if (m_impl->ctx) llama_free(m_impl->ctx);
        if (m_impl->model) llama_model_free(m_impl->model);
        delete m_impl;
        m_impl = nullptr;
    }
}

bool sys_scan::ui::AgentService::loadModel(const QString& modelPath) {
#ifdef LLAMA_API_VERSION
    if (m_impl->sampler) { llama_sampler_free(m_impl->sampler); m_impl->sampler = nullptr; }
    if (m_impl->ctx) { llama_free(m_impl->ctx); m_impl->ctx = nullptr; }
    if (m_impl->model) { llama_model_free(m_impl->model); m_impl->model = nullptr; }

    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 99;

    m_impl->model = llama_load_model_from_file(modelPath.toStdString().c_str(), model_params);
    if (!m_impl->model) return false;

    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 2048;
    ctx_params.n_batch = 512;
    
    m_impl->ctx = llama_new_context_with_model(m_impl->model, ctx_params);
    
    if (m_impl->ctx) {
        m_impl->sampler = llama_sampler_chain_init(llama_sampler_chain_default_params());
        llama_sampler_chain_add(m_impl->sampler, llama_sampler_init_temp(0.8f));
        llama_sampler_chain_add(m_impl->sampler, llama_sampler_init_top_k(40));
        llama_sampler_chain_add(m_impl->sampler, llama_sampler_init_top_p(0.95f, 1));
        llama_sampler_chain_add(m_impl->sampler, llama_sampler_init_dist(1234));
    }

    return (m_impl->ctx != nullptr);
#else
    Q_UNUSED(modelPath);
    return false;
#endif
}

namespace {
    sys_scan::ui::Generator<QString> ask_internal(sys_scan::ui::AgentServiceImpl* impl, std::string prompt) {
        if (!impl || !impl->model || !impl->ctx) {
             co_yield "Error: Model not loaded.";
             co_return;
        }

        const llama_vocab* vocab = llama_model_get_vocab(impl->model);
        const int n_ctx = llama_n_ctx(impl->ctx);
        std::vector<llama_token> tokens_list(n_ctx);
        
        int n_tokens = llama_tokenize(vocab, prompt.c_str(), prompt.length(), tokens_list.data(), tokens_list.size(), true, true);
        
        if (n_tokens < 0) {
             co_yield "Error: Prompt too long.";
             co_return;
        }
        tokens_list.resize(n_tokens);

        llama_batch batch = llama_batch_init(512, 0, 1);

        if (n_tokens > 0) {
            batch.n_tokens = n_tokens;
            for (int i = 0; i < n_tokens; ++i) {
                batch.token[i] = tokens_list[i];
                batch.pos[i] = i;
                batch.n_seq_id[i] = 0;
                batch.seq_id[i] = nullptr;
                batch.logits[i] = (i == n_tokens - 1) ? 1 : 0;
            }

            if (llama_decode(impl->ctx, batch) != 0) {
                co_yield "Error: Decode failed.";
                llama_batch_free(batch);
                co_return;
            }
        }

        int n_decode = 0;
        const int max_gen = 512;

        while (n_decode < max_gen) {
            llama_token new_token_id = llama_sampler_sample(impl->sampler, impl->ctx, -1);

            if (llama_vocab_is_eog(vocab, new_token_id)) {
                break;
            }

            char buf[256];
            int n = llama_token_to_piece(vocab, new_token_id, buf, sizeof(buf), 0, true);
            if (n > 0) {
                std::string piece(buf, n);
                co_yield QString::fromStdString(piece);
            }

            batch.n_tokens = 1;
            batch.token[0] = new_token_id;
            batch.pos[0] = n_tokens + n_decode;
            batch.n_seq_id[0] = 0;
            batch.seq_id[0] = nullptr;
            batch.logits[0] = 1;

            if (llama_decode(impl->ctx, batch) != 0) break;
            n_decode++;
        }
        
        llama_batch_free(batch);
    }
}

void sys_scan::ui::AgentService::promptAsync(const QString& prompt) {
    std::thread([this, p = prompt.toStdString()]() {
        for (auto token : ask_internal(m_impl, p)) {
            QMetaObject::invokeMethod(this, [this, t = token]() {
                emit tokenReceived(t);
            });
        }
        QMetaObject::invokeMethod(this, [this]() {
            emit generationFinished();
        });
    }).detach();
}