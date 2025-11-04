#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

// ======================
// HẰNG SỐ MẶC ĐỊNH
// ======================
struct Defaults {
    static constexpr int    K_FREQUENT   = 3;
    static constexpr int    D_PREFIX     = 4;
    static constexpr int    MAX_CHILDREN = 3;
    static constexpr double THETA_MATCH  = 0.50;
    static constexpr bool   USE_PREFIX_WILDCARD_IF_OVERFLOW = true;
};

// ======================
// KIỂU DỮ LIỆU CỦA CÂY
// ======================
struct TemplateInfo {
    int tid = -1;                              // template ID
    std::vector<std::string> tokens;           // nội dung template
    int count = 0;                             // số log gộp vào template
    std::vector<int> log_ids;                  // danh sách ID các log thuộc template

    TemplateInfo() = default;
    TemplateInfo(int id, const std::vector<std::string>& t, int first_log_id)
        : tid(id), tokens(t), count(1)
    {
        log_ids.push_back(first_log_id);
    }
};

// ======================
// NÚT TRONG CÂY TRIE
// ======================
struct TrieNode {
    std::unordered_map<std::string, TrieNode*> children; 
    std::vector<TemplateInfo> clusters; 

    ~TrieNode() {
        for (auto &kv : children) delete kv.second;
    }
};

// ======================
// CẤU HÌNH CHẠY
// ======================
struct TraverseParams {
    int    K_frequent   = Defaults::K_FREQUENT;
    int    d_prefix     = Defaults::D_PREFIX;
    int    max_children = Defaults::MAX_CHILDREN;
    double theta_match  = Defaults::THETA_MATCH;
    bool   use_prefix_wildcard_if_overflow = Defaults::USE_PREFIX_WILDCARD_IF_OVERFLOW;

    std::string wildcard_any;
    std::unordered_set<std::string> wildcard_tokens;
    const std::unordered_set<std::string>* stopwords = nullptr;
    std::unordered_map<std::string, std::string> placeholder_regex;
};

// Alias
using GlobalFreq = std::unordered_map<std::string, int>;
