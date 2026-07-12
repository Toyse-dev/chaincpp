#include "chaincpp/rag/vector_store.hpp"
#include "chaincpp/core/prompt.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>

namespace chaincpp::rag {

// InMemoryVectorStore Implementation

std::unique_ptr<InMemoryVectorStore> InMemoryVectorStore::create() {
    return std::unique_ptr<InMemoryVectorStore>(new InMemoryVectorStore());
}

security::Result<void> InMemoryVectorStore::add_documents(
    const std::vector<Document>& documents,
    const std::vector<std::vector<float>>& embeddings
) {
    if (documents.size() != embeddings.size()) {
        return security::Result<void>::err("Documents and embeddings size mismatch");
    }
    
    for (size_t i = 0; i < documents.size(); ++i) {
        // Prevent vector dimension out-of-bounds corruption
        if (!documents_.empty() && embeddings[i].size() != documents_[0].embedding.size()) {
            return security::Result<void>::err("Dimensionality mismatch: Matrix does not conform to current vector store index parameters.");
        }

        StoredDocument stored;
        stored.doc = documents[i];
        stored.embedding = embeddings[i];
        documents_.push_back(std::move(stored));
    }
    
    return security::Result<void>::ok();
}

security::Result<void> InMemoryVectorStore::add_document(
    const Document& document,
    EmbeddingModel& embedding_model
) {
    auto embedding_result = embedding_model.embed(document.page_content);
    if (embedding_result.is_err()) {
        return security::Result<void>::err(embedding_result.error());
    }
    
    StoredDocument stored;
    stored.doc = document;
    stored.embedding = std::move(embedding_result.value());
    documents_.push_back(std::move(stored));
    
    return security::Result<void>::ok();
}

security::Result<std::vector<std::pair<Document, float>>> 
InMemoryVectorStore::similarity_search(
    const std::vector<float>& query_embedding,
    size_t k
) {
    if (documents_.empty()) {
        return security::Result<std::vector<std::pair<Document, float>>>::ok({});
    }
    
    // Calculate similarities
    std::vector<std::pair<size_t, float>> similarities;
    similarities.reserve(documents_.size());
    
    for (size_t i = 0; i < documents_.size(); ++i) {
        float sim = cosine_similarity(query_embedding, documents_[i].embedding);
        similarities.push_back({i, sim});
    }
    
    // Sort by similarity (descending)
    std::sort(similarities.begin(), similarities.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Take top k
    k = std::min(k, similarities.size());
    std::vector<std::pair<Document, float>> results;
    results.reserve(k);
    
    for (size_t i = 0; i < k; ++i) {
        results.push_back({documents_[similarities[i].first].doc, similarities[i].second});
    }
    
    return security::Result<std::vector<std::pair<Document, float>>>::ok(std::move(results));
}

security::Result<std::vector<std::pair<Document, float>>> 
InMemoryVectorStore::similarity_search_by_text(
    const std::string& query,
    EmbeddingModel& embedding_model,
    size_t k
) {
    auto embedding_result = embedding_model.embed(query);
    if (embedding_result.is_err()) {
        return security::Result<std::vector<std::pair<Document, float>>>::err(embedding_result.error());
    }
    
    return similarity_search(embedding_result.value(), k);
}

std::vector<Document> InMemoryVectorStore::get_all_documents() const {
    std::vector<Document> docs;
    docs.reserve(documents_.size());
    for (const auto& stored : documents_) {
        docs.push_back(stored.doc);
    }
    return docs;
}

void InMemoryVectorStore::clear() {
    documents_.clear();
}

size_t InMemoryVectorStore::size() const {
    return documents_.size();
}

float InMemoryVectorStore::cosine_similarity(
    const std::vector<float>& a,
    const std::vector<float>& b
) {
    if (a.empty() || b.empty() || a.size() != b.size()) {
        return 0.0f;
    }
    
    float dot = 0.0f;
    float norm_a = 0.0f;
    float norm_b = 0.0f;
    
    for (size_t i = 0; i < a.size(); ++i) {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    
    if (norm_a == 0.0f || norm_b == 0.0f) {
        return 0.0f;
    }
    
    return dot / (std::sqrt(norm_a) * std::sqrt(norm_b));
}

// RetrievalChain Implementation

class RetrievalChain::Impl {
public:
    Impl(std::unique_ptr<VectorStore> vs, 
         std::unique_ptr<EmbeddingModel> emb,
         std::unique_ptr<models::BaseLLM> llm,
         Config cfg)
        : vector_store_(std::move(vs))
        , embedding_model_(std::move(emb))
        , llm_(std::move(llm))
        , config_(std::move(cfg)) {}
    
    security::Result<std::string> query(const std::string& question) {
        auto result = query_with_sources(question);
        if (result.is_err()) {
            return security::Result<std::string>::err(result.error());
        }
        return security::Result<std::string>::ok(result.value().answer);
    }
    
    security::Result<QueryResult> query_with_sources(const std::string& question) {
        // 1. Retrieve relevant documents
        auto search_result = vector_store_->similarity_search_by_text(
            question, *embedding_model_, config_.top_k
        );
        
        if (search_result.is_err()) {
            return security::Result<QueryResult>::err(search_result.error());
        }
        
        auto retrieved = std::move(search_result.value());
        
        // 2. Build context from retrieved documents
        std::string context;
        for (size_t i = 0; i < retrieved.size(); ++i) {
            context += "Document " + std::to_string(i + 1) + ":\n";
            context += retrieved[i].first.page_content + "\n\n";
        }
        
        // 3. Build prompt
        auto prompt_result = core::PromptTemplate::create(config_.system_prompt_template);
        if (prompt_result.is_err()) {
            return security::Result<QueryResult>::err(prompt_result.error());
        }
        
        auto prompt = prompt_result.value();
        std::map<std::string, std::string> vars = {
            {"context", context},
            {"question", question}
        };
        
        auto formatted = prompt.format(vars);
        if (formatted.is_err()) {
            return security::Result<QueryResult>::err(formatted.error());
        }
        
        // 4. Generate answer
        std::vector<models::Message> messages = {
            models::Message::user(formatted.value())
        };
        
        // ModelConfig to resolve parameter ambiguity
        models::ModelConfig llm_cfg;
        auto response = llm_->generate(messages, llm_cfg);
        if (response.is_err()) {
            return security::Result<QueryResult>::err(response.error());
        }
        
        // 5. Build result
        QueryResult result;
        result.answer = response.value();
        if (config_.include_source_documents) {
            result.source_documents = std::move(retrieved);
        }
        
        return security::Result<QueryResult>::ok(std::move(result));
    }
    
    security::Result<void> add_documents(const std::vector<Document>& documents) {
        // Embed all documents
        std::vector<std::string> texts;
        texts.reserve(documents.size());
        for (const auto& doc : documents) {
            texts.push_back(doc.page_content);
        }
        
        auto embeddings = embedding_model_->embed_batch(texts);
        if (embeddings.is_err()) {
            return security::Result<void>::err(embeddings.error());
        }
        
        return vector_store_->add_documents(documents, embeddings.value());
    }
    
private:
    std::unique_ptr<VectorStore> vector_store_;
    std::unique_ptr<EmbeddingModel> embedding_model_;
    std::unique_ptr<models::BaseLLM> llm_;
    Config config_;
};

// RetrievalChain Public API
security::Result<std::unique_ptr<RetrievalChain>> RetrievalChain::create(
    std::unique_ptr<VectorStore> vector_store,
    std::unique_ptr<EmbeddingModel> embedding_model,
    std::unique_ptr<models::BaseLLM> llm
) {
    return create(std::move(vector_store), std::move(embedding_model), std::move(llm), Config());
}

security::Result<std::unique_ptr<RetrievalChain>> RetrievalChain::create(
    std::unique_ptr<VectorStore> vector_store,
    std::unique_ptr<EmbeddingModel> embedding_model,
    std::unique_ptr<models::BaseLLM> llm,
    Config config
) {
    if (!vector_store || !embedding_model || !llm) {
        return security::Result<std::unique_ptr<RetrievalChain>>::err(
            "Vector store, embedding model, and LLM are required"
        );
    }
    
    auto chain = std::unique_ptr<RetrievalChain>(new RetrievalChain());
    chain->impl_ = std::make_unique<Impl>(
        std::move(vector_store),
        std::move(embedding_model),
        std::move(llm),
        std::move(config)
    );
    
    return security::Result<std::unique_ptr<RetrievalChain>>::ok(std::move(chain));
}

RetrievalChain::~RetrievalChain() = default;

security::Result<std::string> RetrievalChain::query(const std::string& question) {
    return impl_->query(question);
}

security::Result<RetrievalChain::QueryResult> RetrievalChain::query_with_sources(
    const std::string& question
) {
    return impl_->query_with_sources(question);
}

security::Result<void> RetrievalChain::add_documents(const std::vector<Document>& documents) {
    return impl_->add_documents(documents);
}

} // namespace chaincpp::rag