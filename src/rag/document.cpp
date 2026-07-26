#include "chaincpp/rag/document.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <random>
#include <iomanip>
#include <algorithm>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace chaincpp::rag {

// Document Implementation
void Document::ensure_id() {
    if (id.empty()) {
        // Generate a unique ID
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 16; ++i) {
            ss << std::setw(1) << dis(gen);
        }
        id = ss.str();
    }
}

std::string Document::to_json() const {
    json j;
    j["id"] = id;
    j["page_content"] = page_content;
    j["metadata"] = metadata;
    return j.dump();
}

security::Result<Document> Document::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);
        
        Document doc;
        doc.id = j.value("id", "");
        doc.page_content = j.value("page_content", "");
        
        if (j.contains("metadata")) {
            for (auto& [key, value] : j["metadata"].items()) {
                doc.metadata[key] = value.get<std::string>();
            }
        }
        
        doc.ensure_id();
        return security::Result<Document>::ok(std::move(doc));
    } catch (const std::exception& e) {
        return security::Result<Document>::err("Failed to parse document: " + std::string(e.what()));
    }
}

// DocumentChunk Implementation
Document DocumentChunk::to_document() const {
    Document doc;
    doc.page_content = content;
    doc.metadata = metadata;
    doc.metadata["chunk_index"] = std::to_string(chunk_index);
    doc.metadata["total_chunks"] = std::to_string(total_chunks);
    doc.metadata["parent_id"] = parent_id;
    doc.ensure_id();
    return doc;
}

// TextSplitter Implementation
TextSplitter::TextSplitter(Config config) : config_(std::move(config)) {}

std::vector<std::string> TextSplitter::split_with_separators(const std::string& text) const {
    std::vector<std::string> splits;
    std::string current = text;
    
    for (const auto& separator : config_.separators) {
        if (separator.empty()) {
            // Split into individual characters
            for (char c : current) {
                splits.push_back(std::string(1, c));
            }
            current.clear();
            break;
        }
        
        std::vector<std::string> new_splits;
        size_t pos = 0;
        size_t found = current.find(separator);
        
        while (found != std::string::npos) {
            std::string piece = current.substr(pos, found - pos);
            if (!piece.empty()) {
                new_splits.push_back(piece);
            }
            
            if (config_.keep_separator) {
                new_splits.push_back(separator);
            }
            
            pos = found + separator.length();
            found = current.find(separator, pos);
        }
        
        if (pos < current.length()) {
            new_splits.push_back(current.substr(pos));
        }
        
        if (!new_splits.empty()) {
            splits = std::move(new_splits);
            current.clear();
            break;
        }
    }
    
    if (splits.empty() && !text.empty()) {
        splits.push_back(text);
    }
    
    return splits;
}

std::vector<std::string> TextSplitter::merge_splits(const std::vector<std::string>& splits) const {
    std::vector<std::string> merged;
    std::string current;
    
    for (const auto& split : splits) {
        if (current.empty()) {
            current = split;
        } else if (current.length() + split.length() <= config_.chunk_size) {
            current += split;
        } else {
            merged.push_back(current);
            // Add overlap
            size_t overlap_start = current.length() > config_.chunk_overlap ? 
                                   current.length() - config_.chunk_overlap : 0;
            current = current.substr(overlap_start) + split;
        }
    }
    
    if (!current.empty()) {
        merged.push_back(current);
    }
    
    return merged;
}

std::vector<std::string> TextSplitter::split_text(const std::string& text) const {
    auto splits = split_with_separators(text);
    return merge_splits(splits);
}

std::vector<DocumentChunk> TextSplitter::split_document(const Document& doc) const {
    std::vector<DocumentChunk> chunks;
    auto text_chunks = split_text(doc.page_content);
    
    for (size_t i = 0; i < text_chunks.size(); ++i) {
        DocumentChunk chunk;
        chunk.content = text_chunks[i];
        chunk.metadata = doc.metadata;
        chunk.parent_id = doc.id;
        chunk.chunk_index = i;
        chunk.total_chunks = text_chunks.size();
        chunks.push_back(std::move(chunk));
    }
    
    return chunks;
}

std::vector<DocumentChunk> TextSplitter::split_documents(const std::vector<Document>& docs) const {
    std::vector<DocumentChunk> all_chunks;
    for (const auto& doc : docs) {
        auto chunks = split_document(doc);
        all_chunks.insert(all_chunks.end(), 
                          std::make_move_iterator(chunks.begin()),
                          std::make_move_iterator(chunks.end()));
    }
    return all_chunks;
}

// DocumentLoader Implementation
static bool is_path_allowlisted(const std::string& target, const std::vector<std::string>& allowed_paths) {
    try {
        for (const auto& allowed : allowed_paths) {
            fs::path base = fs::absolute(allowed);
            fs::path target_path = fs::absolute(target);

            // Canonicalize paths to resolve any hidden relative symlinks ("..")
            if (fs::exists(base)) base = fs::canonical(base);
            if (fs::exists(target_path)) target_path = fs::canonical(target_path);
            
            auto distance = std::distance(base.begin(), base.end());
            auto target_distance = std::distance(target_path.begin(), target_path.end());
            
            if (target_distance >= distance && std::equal(base.begin(), base.end(), target_path.begin())) {
                return true; 
            }
        }
    } catch (...) {
        return false;
    }
    return false;
}

security::Result<Document> DocumentLoader::load_text_file(const std::string& filepath, const std::vector<std::string>& allowed_paths) {
    // Enforce defense in depth path checking
    if (!is_path_allowlisted(filepath, allowed_paths)) {
        return security::Result<Document>::err("Security Access Denied: Path traversal attempt blocked for " + filepath);
    }

    std::ifstream file(filepath);
    if (!file) {
        return security::Result<Document>::err("Cannot open file: " + filepath);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    Document doc;
    doc.page_content = buffer.str();
    doc.metadata["source"] = filepath;
    doc.ensure_id();
    
    return security::Result<Document>::ok(std::move(doc));
}

security::Result<std::vector<Document>> DocumentLoader::load_text_directory(
    const std::string& dirpath,
    const std::vector<std::string>& allowed_paths
) {
    // Enforce defense-indepth path checking
    if (!is_path_allowlisted(dirpath, allowed_paths)) {
        return security::Result<std::vector<Document>>::err("Security Access Denied: Directory path outside allowed sandbox boundaries.");
    }
    
    std::vector<Document> docs;
    
    try {
        for (const auto& entry : fs::directory_iterator(dirpath)) {
            if (entry.is_regular_file()) {
                auto path = entry.path();
                if (path.extension() == ".txt") {
                    auto doc_result = load_text_file(path.string());
                    if (doc_result.is_ok()) {
                        docs.push_back(std::move(doc_result.value()));
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        return security::Result<std::vector<Document>>::err("Failed to read directory: " + std::string(e.what()));
    }
    
    return security::Result<std::vector<Document>>::ok(std::move(docs));
}

Document DocumentLoader::from_string(const std::string& content, const std::string& source) {
    Document doc;
    doc.page_content = content;
    doc.metadata["source"] = source;
    doc.ensure_id();
    return doc;
}

security::Result<Document> DocumentLoader::from_json_string(const std::string& json_str) {
    return Document::from_json(json_str);
}

security::Result<std::vector<Document>> DocumentLoader::from_json_array(const std::string& json_str) {
    try {
        json j = json::parse(json_str);
        if (!j.is_array()) {
            return security::Result<std::vector<Document>>::err("Expected JSON array");
        }
        
        std::vector<Document> docs;
        for (const auto& item : j) {
            Document doc;
            doc.id = item.value("id", "");
            doc.page_content = item.value("page_content", "");
            
            if (item.contains("metadata")) {
                for (auto& [key, value] : item["metadata"].items()) {
                    doc.metadata[key] = value.get<std::string>();
                }
            }
            
            doc.ensure_id();
            docs.push_back(std::move(doc));
        }
        
        return security::Result<std::vector<Document>>::ok(std::move(docs));
    } catch (const std::exception& e) {
        return security::Result<std::vector<Document>>::err("Failed to parse JSON: " + std::string(e.what()));
    }
}

} // namespace chaincpp::rag