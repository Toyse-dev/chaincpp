#include <iostream>
#include <chrono>
#include <string>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include "llama.h"

#ifdef __unix__
#include <sys/resource.h>
#endif

size_t get_peak_rss_mb() {
#ifdef __unix__
    struct rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
#ifdef __APPLE__
    return usage.ru_maxrss / 1024 / 1024;
#else
    return usage.ru_maxrss / 1024;
#endif
#else
    return 0;
#endif
}

int main(int argc, char** argv) {
    const char* model_path = std::getenv("TINYLLAMA_GGUF");
    if (!model_path) model_path = "models/tinyllama.gguf";
    if (argc > 1) model_path = argv[1];

    int n_predict = 128;
    if (argc > 2) n_predict = std::atoi(argv[2]);

    std::cout << "Model: " << model_path << "\n";

    llama_backend_init();

    llama_model_params mparams = llama_model_default_params();
    llama_model* model = llama_load_model_from_file(model_path, mparams);
    if (!model) {
        std::cerr << "Failed to load model: " << model_path << "\n";
        return 1;
    }

    llama_context_params cparams = llama_context_default_params();
    cparams.n_ctx = 2048;
    cparams.n_threads = 4;
    llama_context* ctx = llama_new_context_with_model(model, cparams);
    if (!ctx) {
        std::cerr << "Failed to create context\n";
        llama_free_model(model);
        return 1;
    }

    llama_sampler_chain_params sparams = llama_sampler_chain_default_params();
    llama_sampler* smpl = llama_sampler_chain_init(sparams);
    llama_sampler_chain_add(smpl, llama_sampler_init_temp(0.7f));
    llama_sampler_chain_add(smpl, llama_sampler_init_dist(LLAMA_DEFAULT_SEED));

    std::string prompt = "Write a story about a robot learning to code:";
    std::vector<llama_token> tokens(prompt.size() + 128); 
    int n_tokens = llama_tokenize(model, prompt.c_str(), (int)prompt.size(), tokens.data(), (int)tokens.size(), true, true);
    if (n_tokens < 0) {
        tokens.resize(-n_tokens);
        n_tokens = llama_tokenize(model, prompt.c_str(), (int)prompt.size(), tokens.data(), (int)tokens.size(), true, true);
    }
    tokens.resize(n_tokens);

    for (auto id : tokens) {
        char buf[128];
        int n = llama_token_to_piece(model, id, buf, sizeof(buf), 0, true);
        if (n > 0) std::cout << std::string(buf, n);
    }
    std::cout << std::flush;

    // b4242 compatible batch - manual fill, no llama_batch_add
    llama_batch batch = llama_batch_init(512, 0, 1);
    batch.n_tokens = n_tokens;
    for (int i = 0; i < n_tokens; i++) {
        batch.token[i] = tokens[i];
        batch.pos[i] = i;
        batch.n_seq_id[i] = 1;
        batch.seq_id[i][0] = 0;
        batch.logits[i] = false;
    }
    batch.logits[batch.n_tokens - 1] = true;

    if (llama_decode(ctx, batch) != 0) {
        std::cerr << "Failed to decode prompt\n";
        return 1;
    }

    auto start = std::chrono::high_resolution_clock::now();
    int n_gen = 0;
    int n_past = tokens.size();

    while (n_gen < n_predict) {
        llama_token new_token = llama_sampler_sample(smpl, ctx, -1);
        
        if (llama_token_is_eog(model, new_token)) {
            break;
        }

        char buf[128];
        int n = llama_token_to_piece(model, new_token, buf, sizeof(buf), 0, true);
        if (n > 0) {
            std::cout << std::string(buf, n) << std::flush;
        }

        // manual single token batch for b4242
        batch.n_tokens = 1;
        batch.token[0] = new_token;
        batch.pos[0] = n_past;
        batch.n_seq_id[0] = 1;
        batch.seq_id[0][0] = 0;
        batch.logits[0] = true;
        
        if (llama_decode(ctx, batch) != 0) {
            std::cerr << "Failed to decode token\n";
            break;
        }

        n_past++;
        n_gen++;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto gen_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double tps = (n_gen * 1000.0) / std::max<int64_t>(gen_ms, 1);

    std::cout << "\n========================================\n";
    std::cout << "Generated " << n_gen << " tokens in " << gen_ms << " ms\n";
    std::cout << "Tokens/sec: " << tps << "\n";
    std::cout << "Peak RSS: " << get_peak_rss_mb() << " MB\n";
    std::cout << "========================================\n";
    std::cout << "\nCSV: chaincpp," << tps << "," << get_peak_rss_mb() << "\n";

    llama_batch_free(batch);
    llama_sampler_free(smpl);
    llama_free(ctx);
    llama_free_model(model);
    llama_backend_free();

    return 0;
}
