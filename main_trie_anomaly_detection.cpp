#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <functional>
#include "trie_anomaly_detection.hpp"

using namespace std;
namespace fs = std::filesystem;

static vector<string> list_txt_files(const string& dir) {
    vector<string> files;
    if (!fs::exists(dir)) return files;
    for (auto& p : fs::directory_iterator(dir)) {
        if (p.is_regular_file()) {
            auto ext = p.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".txt") files.push_back(p.path().string());
        }
    }
    sort(files.begin(), files.end());
    return files;
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    const string input_dir   = "./input";
    const string output_dir  = "./output";
    const string unified_tpl = output_dir + "/templates.csv";
    const string output_logmap = output_dir + "/log_anomaly_mapping.csv";
    const string output_anom   = output_dir + "/logs_anomaly_only.csv";

    auto files = list_txt_files(input_dir);
    if (files.empty()) { cerr << "[ERROR] No .txt files found in " << input_dir << "\n"; return 1; }
    if (!fs::exists(output_dir)) fs::create_directory(output_dir);

    preprocess pre;
    internal_node_traverse INT;
    trie_update updater;
    TrieNode* root = new TrieNode();
    unordered_map<string,int> global_freq;
    int next_tid = 1, log_id = 1;

    // --- Warm-up header model: 30 dòng đầu từ file đầu tiên ---
    {
        ifstream f0(files.front());
        if (!f0.is_open()) { cerr << "[ERROR] Cannot open " << files.front() << "\n"; delete root; return 1; }
        string line; size_t cnt = 0;
        while (cnt < 30 && getline(f0, line)) {
            if (line.empty()) continue;
            INT.header_model_observe(pre.preprocess_line(line));
            ++cnt;
        }
        INT.header_model_finalize();
        f0.close();
    }

    // --- Đọc tất cả file .txt theo thứ tự tên ---
    size_t file_idx = 0;
    for (const auto& path : files) {
        ifstream fin(path);
        if (!fin.is_open()) { cerr << "[WARN] Skip unreadable file: " << path << "\n"; continue; }
        cout << "[INFO] Ingesting: " << path << "\n";
        string line;
        while (getline(fin, line)) {
            if (line.empty()) { ++log_id; continue; }
            auto tokens = pre.preprocess_line(line);
            InsertResult res = INT.insert_strict_with_body(root, tokens, global_freq, next_tid, log_id);
            cout << "[LOG#" << log_id << "] -> ";
            if (res.kind == InsertResult::EXACT_MATCH) cout << "EXACT";
            else if (res.kind == InsertResult::PARTIAL_OR_UPDATED) cout << "MERGED";
            else cout << "NEW";
            cout << " (TID=" << res.tid << ")\n";
            if (log_id % 10000 == 0) updater.run_bottom_up_updates(root, global_freq, next_tid);
            ++log_id;
        }
        fin.close();
        ++file_idx;
    }
    next_tid = trie_update::renumber_tids_in_tree(root, 1);

    cout << "[INFO] Files=" << files.size()
         << " | Logs=" << (log_id-1)
         << " | Templates=" << (next_tid-1) << "\n";

    // --- Collect templates ---
    vector<TemplateInfo> all_templates;
    function<void(const TrieNode*)> dfs_collect = [&](const TrieNode* node) {
        if (!node) return;
        for (auto &kv : node->children) dfs_collect(kv.second);
        for (const auto &tpl : node->clusters) all_templates.push_back(tpl);
    };
    dfs_collect(root);

    // --- Anomaly scoring (EVT) ---
    anomaly_detection detector;
    auto scored_templates = detector.compute_from_templates(all_templates);
    double threshold = detector.last_threshold();
    unordered_map<int,double> score_map;
    for (auto &r : scored_templates) score_map[r.info.tid] = r.score;
    cout << "[INFO] EVT threshold = " << threshold << "\n";

    // --- templates.csv ---
    {
        ofstream fo(unified_tpl);
        if (!fo.is_open()) { cerr << "[ERROR] Cannot create " << unified_tpl << "\n"; delete root; return 1; }
        fo << "threshold," << std::fixed << std::setprecision(9) << threshold << ",N/A,N/A,N/A" << "\n";;
        fo << "tid,count,score,anomaly_win,template\n";
        function<void(const TrieNode*)> dfs_write = [&](const TrieNode* node) {
            if (!node) return;
            for (auto &kv : node->children) dfs_write(kv.second);
            for (const auto &tpl : node->clusters) {
                double s = score_map.count(tpl.tid) ? score_map[tpl.tid] : 0.0;
                bool is_anom = (s + 1e-9 >= threshold);
                fo << tpl.tid << "," << tpl.count << "," << s << "," << (is_anom?1:0) << ",\"";
                for (size_t i=0;i<tpl.tokens.size();++i){ fo << tpl.tokens[i]; if (i+1<tpl.tokens.size()) fo << " "; }
                fo << "\"\n";
            }
        };
        dfs_write(root);
        fo.close();
        cout << "[INFO] Wrote " << unified_tpl << "\n";
    }

    // --- Build log map (log_id → tid, score, anomaly, template_text) ---
    struct LogRec { int tid; double score; bool anom; string tpl; };
    unordered_map<int, LogRec> logmap; logmap.reserve(1u<<16);
    {
        function<void(const TrieNode*)> dfs_logs = [&](const TrieNode* node) {
            if (!node) return;
            for (auto &kv : node->children) dfs_logs(kv.second);
            for (const auto &tpl : node->clusters) {
                double s = score_map.count(tpl.tid) ? score_map[tpl.tid] : 0.0;
                bool is_anom = (s + 1e-9 >= threshold);
                stringstream ss;
                for (size_t i=0;i<tpl.tokens.size();++i){ ss << tpl.tokens[i]; if (i+1<tpl.tokens.size()) ss << " "; }
                string txt = ss.str();
                for (int id : tpl.log_ids) logmap[id] = {tpl.tid, s, is_anom, txt};
            }
        };
        dfs_logs(root);
    }

    // --- log_anomaly_mapping.csv ---
    {
        ofstream fo(output_logmap);
        if (!fo.is_open()) { cerr << "[ERROR] Cannot create " << output_logmap << "\n"; delete root; return 1; }
        fo << "log_id,anomaly_win,template_id,template\n";
        vector<int> ids; ids.reserve(logmap.size());
        for (auto &kv : logmap) ids.push_back(kv.first);
        sort(ids.begin(), ids.end());
        for (int id : ids) {
            const auto &r = logmap[id];
            fo << id << "," << (r.anom?1:0) << "," << r.tid << ",\"" << r.tpl << "\"\n";
        }
        fo.close();
        cout << "[INFO] Wrote " << output_logmap << "\n";
    }

    // --- logs_anomaly_only.csv: đọc lại toàn bộ file theo thứ tự, xuất dòng bất thường ---
    {
        ofstream fo(output_anom);
        if (!fo.is_open()) { cerr << "[ERROR] Cannot create " << output_anom << "\n"; }
        else {
            fo << "log_id,template_id,score,raw_log\n";
            int cur_id = 1;
            for (const auto& path : files) {
                ifstream fr(path);
                if (!fr.is_open()) { cerr << "[WARN] Skip raw export (cannot open): " << path << "\n"; continue; }
                string line;
                while (getline(fr, line)) {
                    auto it = logmap.find(cur_id);
                    if (it != logmap.end() && it->second.anom) {
                        for (char &c : line) if (c=='"') c = '\'';
                        fo << cur_id << "," << it->second.tid << ","
                           << fixed << setprecision(6) << it->second.score
                           << ",\"" << line << "\"\n";
                    }
                    ++cur_id;
                }
                fr.close();
            }
            fo.close();
            cout << "[INFO] Wrote " << output_anom << "\n";
        }
    }

    delete root;
    cout << "[FINISHED]\n";
    return 0;
}


