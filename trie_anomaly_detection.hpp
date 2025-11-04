#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <cmath>
#include <algorithm>
#include <functional>
#include "defination.hpp"

using std::string;
using std::vector;
using std::unordered_map;
using std::unordered_set;
using std::regex;

// ======================
// Global settings
// ======================
inline int    D_PREFIX     = 3;
inline int    MAX_CHILDREN = 3;
inline double THETA_MATCH  = 0.6;
inline bool   USE_PREFIX_WILDCARD_IF_OVERFLOW = true;
inline string WILDCARD_ANY = "<*>";

inline unordered_set<string> STOPWORDS = {
    "the","a","an","to","of","in","on","and","or"
};
inline unordered_set<string> WILDCARD_TOKENS = {"<*>"};
inline unordered_map<string, string> PLACEHOLDER_REGEX = {};

inline unordered_map<string, string> NORMALIZE_REPLACE = {
    {"ip",            "<IP>"},
    {"ipv6",          "<IPV6>"},
    {"ip_port_v4",    "<IP_PORT>"},
    {"email",         "<EMAIL>"},
    {"url",           "<URL>"},
    {"uuid",          "<UUID>"},
    {"ts_iso",        "<TIMESTAMP>"},
    {"ts_iso_naive",  "<TIMESTAMP>"},
    {"date_dash",     "<DATE>"},
    {"time_hms",      "<TIME>"},
    {"path_win",      "<PATH>"},
    {"path_unix",     "<PATH>"},
    {"size_bytes",    "<SIZE>"},
    {"percent",       "<PERCENT>"},
    {"hex_0x",        "<HEX>"},
    {"sha256",        "<SHA256>"},
    {"md5",           "<MD5>"},
    {"http_status_line", "<HTTP_STATUS>"},
    {"http_method",   "<HTTP_METHOD>"},
    {"pid",           "<PID>"},
    {"errno",         "<ERRNO>"},
    {"num_sci",       "<NUM>"},
    {"num_float",     "<NUM>"},
    {"num_int",       "<NUM>"},
    {"dev_path",      "<DEVICE>"},
    {"hostname",      "<HOSTNAME>"},
    {"logfile",       "<LOGFILE>"},
};

inline vector<std::pair<string, regex>> make_normalize_sequence() {
    using std::regex_constants::icase;
    vector<std::pair<string, regex>> v;
    v.emplace_back("ip_port_v4", regex(R"(\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}):\d{1,5}\b)"));
    v.emplace_back("ipv6",       regex(R"(\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b)"));
    v.emplace_back("ip",         regex(R"(\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b)"));
    v.emplace_back("email",      regex(R"(\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b)"));
    v.emplace_back("uuid",       regex(R"(\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}\b)"));
    v.emplace_back("url",        regex(R"(\b(?:https?|ftp)://[^\s]+)"));
    v.emplace_back("ts_iso",       regex(R"(\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})\b)"));
    v.emplace_back("ts_iso_naive", regex(R"(\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b)"));
    v.emplace_back("date_dash",    regex(R"(\b\d{4}-\d{2}-\d{2}\b)"));
    v.emplace_back("time_hms",     regex(R"(\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b)"));
    v.emplace_back("path_win",   regex(R"(\b[A-Za-z]:\\[^\s<>|:"?*]+)"));
    v.emplace_back("path_unix",  regex(R"(\b/(?:[^\s]|\\ )+)"));
    v.emplace_back("size_bytes", regex(R"(\b\d+(?:\.\d+)?\s?(?:B|KB|MB|GB|TB|PB)\b)", icase));
    v.emplace_back("percent",    regex(R"(\b\d+(?:\.\d+)?%)"));
    v.emplace_back("hex_0x",     regex(R"(\b0x[0-9A-Fa-f]+\b)"));
    v.emplace_back("sha256",     regex(R"(\b[A-Fa-f0-9]{64}\b)"));
    v.emplace_back("md5",        regex(R"(\b[A-Fa-f0-9]{32}\b)"));
    v.emplace_back("http_status_line", regex(R"(\bHTTP\/\d\.\d\s+\d{3}\b)"));
    v.emplace_back("http_method",      regex(R"(\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b)"));
    v.emplace_back("pid",        regex(R"(\bpid\s*[:=]\s*\d+\b)", icase));
    v.emplace_back("errno",      regex(R"(\berrno\s*[:=]\s*\d+\b)", icase));
    v.emplace_back("num_sci",    regex(R"(\b[+\-]?\d+(?:\.\d+)?[eE][+\-]?\d+\b)"));
    v.emplace_back("num_float",  regex(R"(\b[+\-]?(?:\d*\.\d+)\b)"));
    v.emplace_back("num_int",    regex(R"(\b[+\-]?\d+\b)"));
    v.emplace_back("dev_path",   regex(R"(\bdevice\s+device\b)", icase));
    v.emplace_back("hostname",   regex(R"(\b(?:srv|ops|hcm|edge)\S*\b)", icase));
    v.emplace_back("logfile",    regex(R"(\blog\d+\b)", icase));
    return v;
}
inline vector<std::pair<string, regex>> NORMALIZE_SEQUENCE = make_normalize_sequence();

// ======================
// Constant header detector
// ======================
class const_header_detector {
public:
    size_t warmup_lines = 30;
    double tau_share    = 0.80;
    size_t max_positions= 64;
    bool   locked       = false;

    void observe(const vector<string>& toks) {
        if (locked) return;
        ++seen_;
        size_t m = std::min(max_positions, toks.size());
        if (pos_counters_.size() < m) pos_counters_.resize(m);
        for (size_t i = 0; i < m; ++i) pos_counters_[i][toks[i]]++;
        if (seen_ >= warmup_lines) finalize();
    }
    void finalize() {
        if (locked) return;
        size_t anchor = 0;
        for (size_t i = 0; i < pos_counters_.size(); ++i) {
            int best = 0, sum = 0;
            for (auto &kv : pos_counters_[i]) { best = std::max(best, kv.second); sum += kv.second; }
            double share = sum ? double(best)/double(sum) : 0.0;
            if (share >= tau_share) anchor = i + 1; else break;
        }
        anchor_ = anchor; locked = true;
        pos_counters_.clear(); pos_counters_.shrink_to_fit();
    }
    size_t anchor() const { return anchor_; }
    vector<string> slice_after_anchor(const vector<string>& toks) const {
        if (!locked) return toks;
        if (anchor_ >= toks.size()) return {};
        return {toks.begin() + anchor_, toks.end()};
    }

private:
    size_t seen_ = 0, anchor_ = 0;
    vector<unordered_map<string,int>> pos_counters_;
};

// ======================
// 1) Preprocess
// ======================
class preprocess {
public:
    string normalize_line(const string& line) const {
        string out = line;
        for (const auto& kv : NORMALIZE_SEQUENCE) {
            const string& key = kv.first; (void)key;
            out = std::regex_replace(out, kv.second, normalized_label_for_key(kv.first));
        }
        return out;
    }
    vector<string> tokenize(const string& s) const {
        vector<string> out; out.reserve(32);
        size_t i = 0, n = s.size();
        auto is_word = [](unsigned char c){ return std::isalnum(c)||c=='_'; };

        while (i < n) {
            char c = s[i];
            if (c == '<') {
                size_t j = i+1; bool closed=false;
                while (j < n){ if (s[j]=='>'){ closed=true; break; } ++j; }
                if (closed){ out.emplace_back(s.substr(i, j-i+1)); i = j+1; continue; }
            }
            if (std::isspace((unsigned char)c)) { ++i; continue; }
            if (is_word((unsigned char)c)) {
                size_t j = i+1; while (j<n && is_word((unsigned char)s[j])) ++j;
                string tok = s.substr(i, j-i);
                for (char &ch : tok) if (ch>='A' && ch<='Z') ch = char(ch+32);
                out.emplace_back(std::move(tok)); i = j; continue;
            }
            ++i;
        }
        return out;
    }
    vector<string> preprocess_line(const string& line) const {
        return tokenize(normalize_line(line));
    }

private:
    static inline string to_upper_copy(const string& s){
        string o; o.reserve(s.size());
        for(char c:s) o.push_back((c>='a'&&c<='z')?char(c-32):c);
        return o;
    }
    static inline string strip_angles(const string& s){
        return (s.size()>=2 && s.front()=='<' && s.back()=='>') ? s.substr(1, s.size()-2) : s;
    }
    static inline string normalized_label_for_key(const string& key){
        auto it = NORMALIZE_REPLACE.find(key);
        string base = (it!=NORMALIZE_REPLACE.end()) ? strip_angles(it->second) : key;
        return "<" + to_upper_copy(base) + ">";
    }
};

// ======================
// 2) Internal insert + 3) Leaf update
// ======================
struct InsertResult {
    int tid = -1;
    enum Kind { EXACT_MATCH, PARTIAL_OR_UPDATED, NEW_TEMPLATE } kind = NEW_TEMPLATE;
};

class internal_node_traverse {
public:
    InsertResult insert_strict(TrieNode* root,
                               const vector<string>& tokens,
                               unordered_map<string,int>& global_freq,
                               int& next_tid,
                               int log_id) const {
        TrieNode* leaf = descend_strict_path(root, tokens);
        return update_leaf(leaf, tokens, global_freq, next_tid, log_id);
    }

    void header_model_observe(const vector<string>& toks) const { hdr_.observe(toks); }
    void header_model_finalize() const { hdr_.finalize(); }

    InsertResult insert_strict_with_body(TrieNode* root,
                                         const vector<string>& toks_full,
                                         unordered_map<string,int>& global_freq,
                                         int& next_tid,
                                         int log_id) const {
        auto body = hdr_.slice_after_anchor(toks_full);
        TrieNode* leaf = descend_strict_path(root, body);
        return update_leaf(leaf, body, global_freq, next_tid, log_id);
    }

private:
    mutable const_header_detector hdr_;

    TrieNode* descend_strict_path(TrieNode* node,
                                  const vector<string>& toks,
                                  int prefix_depth = D_PREFIX) const {
        if (toks.empty()) return node;
        string len_key = "LEN=" + std::to_string(toks.size());
        if (!node->children.count(len_key)) node->children[len_key] = new TrieNode();
        node = node->children[len_key];

        size_t limit = std::min(static_cast<size_t>(prefix_depth), toks.size());
        for (size_t i = 0; i < limit; ++i) {
            string key = toks[i];
            if (USE_PREFIX_WILDCARD_IF_OVERFLOW &&
                !node->children.count(key) &&
                node->children.size() >= static_cast<size_t>(MAX_CHILDREN)) key = WILDCARD_ANY;
            if (!node->children.count(key)) node->children[key] = new TrieNode();
            node = node->children[key];
        }
        return node;
    }

    static inline bool is_placeholder(const string& tok) {
        return tok.size()>=2 && tok.front()=='<' && tok.back()=='>';
    }
    static void bump_global_frequency(const vector<string>& toks,
                                      unordered_map<string,int>& gfreq) {
        for (const auto &t : toks) if (!is_placeholder(t) && !STOPWORDS.count(t)) ++gfreq[t];
    }
    static void tokenset_filtered(const vector<string>& V, unordered_set<string>& S) {
        S.clear();
        for (const auto& t : V) if (!is_placeholder(t) && !STOPWORDS.count(t)) S.insert(t);
    }
    static double jaccard_similarity_filtered(const vector<string>& A, const vector<string>& B) {
        unordered_set<string> setA, setB; tokenset_filtered(A,setA); tokenset_filtered(B,setB);
        if (setA.empty() && setB.empty()) return 1.0;
        size_t inter = 0;
        if (setA.size() < setB.size()) for (const auto& x:setA) if (setB.count(x)) ++inter;
        else for (const auto& x:setB) if (setA.count(x)) ++inter;
        size_t uni = setA.size()+setB.size()-inter;
        return uni==0 ? 1.0 : double(inter)/double(uni);
    }
    static vector<string> merge_keep_longer_replace_diff(const vector<string>& A,
                                                         const vector<string>& B) {
        const vector<string>& L = (A.size()>=B.size())?A:B;
        const vector<string>& S = (A.size()>=B.size())?B:A;
        vector<string> R = L;
        for (size_t i=0;i<S.size();++i){
            const string& a=R[i]; const string& b=S[i];
            if (a==b) continue;
            if (a==WILDCARD_ANY || b==WILDCARD_ANY || is_placeholder(a) || is_placeholder(b))
                R[i]=WILDCARD_ANY;
            else R[i]=WILDCARD_ANY;
        }
        return R;
    }

    InsertResult update_leaf(TrieNode* leaf,
                             const vector<string>& toks,
                             unordered_map<string,int>& gfreq,
                             int& next_tid,
                             int log_id) const {
        for (auto &tpl : leaf->clusters) {
            bool match = true;
            size_t n = std::max(tpl.tokens.size(), toks.size());
            vector<string> merged(n, WILDCARD_ANY);
            for (size_t i=0;i<n;++i){
                string a = (i<tpl.tokens.size()?tpl.tokens[i]:WILDCARD_ANY);
                string b = (i<toks.size()?toks[i]:WILDCARD_ANY);
                if (a==b){ merged[i]=a; continue; }
                if (a==WILDCARD_ANY){ merged[i]=b; continue; }
                if (b==WILDCARD_ANY){ merged[i]=a; continue; }
                if (is_placeholder(a) || is_placeholder(b)){ match=false; break; }
                match=false; break;
            }
            if (match){
                tpl.tokens = std::move(merged);
                ++tpl.count;
                tpl.log_ids.push_back(log_id);
                bump_global_frequency(toks, gfreq);
                return {tpl.tid, InsertResult::EXACT_MATCH};
            }
        }

        int best_idx=-1; double best_sim=-1.0;
        for (int i=0;i<(int)leaf->clusters.size();++i){
            double s = jaccard_similarity_filtered(leaf->clusters[i].tokens, toks);
            if (s>best_sim){ best_sim=s; best_idx=i; }
        }
        const double JACCARD_TH = std::max(0.40, THETA_MATCH - 0.05);
        if (best_idx!=-1 && best_sim>=JACCARD_TH){
            auto &tpl = leaf->clusters[best_idx];
            tpl.tokens = merge_keep_longer_replace_diff(tpl.tokens, toks);
            ++tpl.count; tpl.log_ids.push_back(log_id);
            bump_global_frequency(toks, gfreq);
            return {tpl.tid, InsertResult::PARTIAL_OR_UPDATED};
        }

        leaf->clusters.emplace_back(TemplateInfo(next_tid++, toks, log_id));
        bump_global_frequency(toks, gfreq);
        return {leaf->clusters.back().tid, InsertResult::NEW_TEMPLATE};
    }
};

// ======================
// 4) Trie update (bottom-up)
// ======================
class trie_update {
public:
    void run_bottom_up_updates(TrieNode* root,
                               unordered_map<string,int>& global_freq,
                               int& next_tid) const {
        if (!root) return;
        bottom_up_rebuild(root, next_tid);
        unordered_map<string,int> new_gf;
        rebuild_global_frequency_from_tree(root, new_gf);
        global_freq.swap(new_gf);
    }

    static int renumber_tids_in_tree(TrieNode* root, int start_tid = 1) {
        int cur = start_tid;
        std::function<void(TrieNode*)> dfs = [&](TrieNode* node){
            if (!node) return;
            for (auto &kv : node->children) dfs(kv.second);
            for (auto &tpl : node->clusters) tpl.tid = cur++;
        };
        dfs(root);
        return cur;
    }

private:
    struct TemplateBundle { vector<string> tokens; int count; vector<int> log_ids; };

    static void collect_templates(TrieNode* node, vector<TemplateBundle>& out){
        if (!node) return;
        for (const auto& t : node->clusters) out.push_back({t.tokens, t.count, t.log_ids});
        for (auto& kv : node->children) collect_templates(kv.second, out);
    }
    static void clear_subtree(TrieNode* node){
        if (!node) return;
        for (auto& kv : node->children){ clear_subtree(kv.second); delete kv.second; }
        node->children.clear(); node->clusters.clear();
    }
    static inline bool is_placeholder(const string& tok){
        return tok.size()>=2 && tok.front()=='<' && tok.back()=='>';
    }
    static double jaccard_similarity_filtered(const vector<string>& A, const vector<string>& B){
        unordered_set<string> setA,setB;
        for (const auto& t:A) if (!is_placeholder(t) && t!=WILDCARD_ANY && !STOPWORDS.count(t)) setA.insert(t);
        for (const auto& t:B) if (!is_placeholder(t) && t!=WILDCARD_ANY && !STOPWORDS.count(t)) setB.insert(t);
        if (setA.empty() && setB.empty()) return 1.0;
        size_t inter=0; for (const auto& x:setA) if (setB.count(x)) ++inter;
        size_t uni = setA.size()+setB.size()-inter;
        return uni==0 ? 1.0 : double(inter)/double(uni);
    }
    static vector<string> merge_tokens(const vector<string>& A, const vector<string>& B){
        size_t n = std::max(A.size(), B.size());
        vector<string> R(n, WILDCARD_ANY);
        for (size_t i=0;i<n;++i){
            string a = (i<A.size()?A[i]:WILDCARD_ANY);
            string b = (i<B.size()?B[i]:WILDCARD_ANY);
            R[i] = (a==b) ? a : WILDCARD_ANY;
        }
        return R;
    }
    static vector<TemplateBundle> merge_similar_templates(vector<TemplateBundle>& seqs){
        vector<TemplateBundle> merged; vector<bool> used(seqs.size(), false);
        for (size_t i=0;i<seqs.size();++i){
            if (used[i]) continue;
            TemplateBundle cur = seqs[i]; used[i]=true;
            for (size_t j=i+1;j<seqs.size();++j){
                if (used[j]) continue;
                if (jaccard_similarity_filtered(cur.tokens, seqs[j].tokens) >= THETA_MATCH){
                    cur.tokens = merge_tokens(cur.tokens, seqs[j].tokens);
                    cur.count += seqs[j].count;
                    cur.log_ids.insert(cur.log_ids.end(), seqs[j].log_ids.begin(), seqs[j].log_ids.end());
                    used[j]=true;
                }
            }
            merged.push_back(std::move(cur));
        }
        return merged;
    }
    static void rebuild_node_as_prefix(TrieNode* node,
                                       const vector<TemplateBundle>& templates,
                                       int& next_tid){
        clear_subtree(node);
        for (const auto& t : templates) {
            TrieNode* cur = node;
            string len_key = "LEN=" + std::to_string(t.tokens.size());
            if (!cur->children.count(len_key)) cur->children[len_key] = new TrieNode();
            cur = cur->children[len_key];
            for (size_t i=0;i<std::min((size_t)D_PREFIX, t.tokens.size());++i){
                string key = t.tokens[i];
                if (USE_PREFIX_WILDCARD_IF_OVERFLOW &&
                    cur->children.size() >= (size_t)MAX_CHILDREN &&
                    !cur->children.count(key)) key = WILDCARD_ANY;
                if (!cur->children.count(key)) cur->children[key] = new TrieNode();
                cur = cur->children[key];
            }
            bool merged=false;
            for (auto& tpl : cur->clusters){
                if (jaccard_similarity_filtered(tpl.tokens, t.tokens) >= THETA_MATCH){
                    tpl.tokens = merge_tokens(tpl.tokens, t.tokens);
                    tpl.count += t.count;
                    tpl.log_ids.insert(tpl.log_ids.end(), t.log_ids.begin(), t.log_ids.end());
                    merged=true; break;
                }
            }
            if (!merged){
                cur->clusters.emplace_back(TemplateInfo(next_tid++, t.tokens, -1));
                auto &tpl = cur->clusters.back();
                tpl.count = t.count; tpl.log_ids = t.log_ids;
            }
        }
    }
    static void bottom_up_rebuild(TrieNode* node, int& next_tid){
        if (!node) return;
        for (auto& kv : node->children) bottom_up_rebuild(kv.second, next_tid);
        vector<TemplateBundle> seqs; collect_templates(node, seqs);
        if (seqs.size() > 3){
            auto merged = merge_similar_templates(seqs);
            rebuild_node_as_prefix(node, merged, next_tid);
        }
    }
    static void rebuild_global_frequency_from_tree(TrieNode* node, unordered_map<string,int>& gf){
        if (!node) return;
        for (const auto &tpl : node->clusters)
            for (const auto &tok : tpl.tokens)
                if (tok != WILDCARD_ANY && !is_placeholder(tok)) gf[tok] += tpl.count;
        for (auto &kv : node->children)
            rebuild_global_frequency_from_tree(kv.second, gf);
    }
};

// ======================
// 5) Anomaly detection (ScaleAD-like: -log p + EVT)
// ======================
struct ScoredTemplate { TemplateInfo info; double score = 0.0; };

struct GEV {
    double mu = 0.0, sigma = 1.0, xi = 0.0;
    void fit(const vector<double>& x) {
        if (x.empty()){ mu=0; sigma=1; xi=0; return; }
        double m=0; for(double v:x) m+=v; m/=x.size();
        double var=0; for(double v:x) var+=(v-m)*(v-m); var/=std::max<size_t>(1,x.size());
        mu=m; sigma=std::max(std::sqrt(var), 1e-12); xi=0.0;
    }
    double quantile(double p) const {
        p = std::clamp(p, 1e-9, 1.0-1e-9);
        if (xi==0.0) return mu - sigma*std::log(-std::log(p));
        return mu + (sigma/xi) * (std::pow(-std::log(p), -xi) - 1.0);
    }
};

inline double fit_evt_threshold_scalead(const vector<double>& scores,
                                        double tail_fraction = 0.05,
                                        double alpha = 1e-3,
                                        bool verbose = true) {
    if (scores.empty()) return 0.0;
    vector<double> s = scores; std::sort(s.begin(), s.end());
    size_t n = s.size();
    size_t start = (size_t)std::floor((1.0 - tail_fraction) * n);
    if (start >= n) start = n>1 ? n-1 : 0;
    vector<double> tail(s.begin()+start, s.end());
    if (tail.size() < 4) {
        size_t idx = (size_t)std::floor((1.0 - alpha) * (n - 1));
        double thr = s[idx];
        if (verbose) std::cout << "[EVT-Fallback] n="<<n<<" q="<<(1.0-alpha)<<" thr="<<thr<<"\n";
        return thr;
    }
    GEV gev; gev.fit(tail);
    double thr = gev.quantile(1.0 - alpha);
    if (verbose) {
        auto mx = *std::max_element(s.begin(), s.end());
        auto mn = *std::min_element(s.begin(), s.end());
        std::cout << "[EVT] tail="<<tail.size()
                  << " mu="<<gev.mu<<" sigma="<<gev.sigma<<" xi="<<gev.xi
                  << " q="<<(1.0-alpha)<<" thr="<<thr
                  << " | min="<<mn<<" max="<<mx<<"\n";
    }
    return thr;
}

class anomaly_detection {
public:
    struct Options {
        double smoothing = 1.0;
        double tail_fraction = 0.05;
        double alpha = 1e-3;
        bool   verbose = true;
    } opt;

    anomaly_detection() = default;
    explicit anomaly_detection(const Options& o): opt(o) {}

    vector<ScoredTemplate> compute_from_templates(const vector<TemplateInfo>& templates) const {
        vector<ScoredTemplate> out; out.reserve(templates.size());
        long long total = 0; for (auto &t:templates) total += std::max(0, t.count);
        double denom = std::max(1.0, (double)total);
        const double k = opt.smoothing;
        const double M = std::max<size_t>(1, templates.size());
        double denom_smoothed = denom + k * M;

        vector<double> scores; scores.reserve(templates.size());
        for (auto &t : templates) {
            double ci = std::max(0, t.count);
            double pi = (ci + k) / denom_smoothed;
            double s  = -std::log(std::max(1e-12, pi));
            out.push_back({t, s});
            scores.push_back(s);
        }
        last_threshold_ = fit_evt_threshold_scalead(scores, opt.tail_fraction, opt.alpha, opt.verbose);
        last_scores_ = scores;
        return out;
    }

    double last_threshold() const { return last_threshold_; }
    const vector<double>& last_scores() const { return last_scores_; }

private:
    mutable double last_threshold_ = 0.0;
    mutable vector<double> last_scores_;
};
