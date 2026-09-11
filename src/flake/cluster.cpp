#include "flake/cluster.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <set>

#include "core/json.h"
#include "flake/category.h"

namespace tg {
namespace {

// Union-find with path compression (single-link clustering below).
struct UnionFind {
    std::map<std::string, std::string> parent;
    std::string find(const std::string& x) {
        std::string root = x;
        while (parent[root] != root) root = parent[root];
        while (parent[x] != root) {
            std::string nxt = parent[x];
            parent[x] = root;
            root = nxt;
        }
        return root;
    }
    void unite(const std::string& a, const std::string& b) {
        parent[find(a)] = find(b);
    }
};

}  // namespace

std::vector<Cluster> computeClusters(const std::vector<std::string>& lines, double minSim,
                                     int minFailures) {
    if (minSim <= 0.0 || minSim > 1.0) minSim = 0.5;
    if (minFailures < 2) minFailures = 2;

    // Parse runs: per-run map of failed test -> last failure message.
    // A test's most recent failure message is tracked for classification.
    std::vector<std::map<std::string, std::string>> failRuns;
    std::map<std::string, std::string> lastMsg;
    std::map<std::string, int> failCount;
    std::map<std::string, int> totalCount;
    for (const std::string& l : lines) {
        std::map<std::string, std::string> failed;
        try {
            JsonValue r = parseJson(l);
            if (!r.isObject() || !r.has("results")) continue;
            const JsonValue& res = r.at("results");
            if (!res.isObject()) continue;
            for (const auto& kv : res.object) {
                std::string status;
                std::string msg;
                if (kv.second.isString()) {
                    status = kv.second.str;  // legacy format
                } else if (kv.second.isObject()) {
                    status = kv.second.getString("s", "");
                    msg = kv.second.getString("m", "");
                } else {
                    continue;
                }
                totalCount[kv.first]++;
                if (status == "F") {
                    failed[kv.first] = msg;
                    failCount[kv.first]++;
                    if (!msg.empty()) lastMsg[kv.first] = msg;
                }
            }
        } catch (const JsonError&) {
            continue;  // skip corrupt lines
        }
        failRuns.push_back(failed);
    }

    // Candidates: tests with enough failures to show a pattern.
    std::vector<std::string> cand;
    for (const auto& kv : failCount) {
        if (kv.second >= minFailures) cand.push_back(kv.first);
    }
    std::sort(cand.begin(), cand.end());

    auto failSet = [&](const std::string& id) {
        std::set<int> s;
        for (std::size_t i = 0; i < failRuns.size(); ++i) {
            if (failRuns[i].find(id) != failRuns[i].end()) s.insert(static_cast<int>(i));
        }
        return s;
    };
    std::map<std::string, std::set<int>> sets;
    for (const std::string& id : cand) sets[id] = failSet(id);

    UnionFind uf;
    for (const std::string& id : cand) uf.parent[id] = id;
    for (std::size_t i = 0; i < cand.size(); ++i) {
        for (std::size_t j = i + 1; j < cand.size(); ++j) {
            const std::set<int>& a = sets[cand[i]];
            const std::set<int>& b = sets[cand[j]];
            std::size_t inter = 0;
            for (int r : a) {
                if (b.find(r) != b.end()) ++inter;
            }
            std::size_t uni = a.size() + b.size() - inter;
            double sim = (uni == 0) ? 0.0 : static_cast<double>(inter) / uni;
            if (sim >= minSim) uf.unite(cand[i], cand[j]);
        }
    }

    std::map<std::string, std::vector<std::string>> groups;
    for (const std::string& id : cand) groups[uf.find(id)].push_back(id);

    std::vector<Cluster> out;
    for (auto& kv : groups) {
        if (kv.second.size() < 2) continue;  // singletons are not clusters
        std::sort(kv.second.begin(), kv.second.end());
        Cluster c;
        c.members = kv.second;
        std::set<int> inter, uni;
        bool first = true;
        for (const std::string& id : c.members) {
            if (first) {
                inter = sets[id];
                first = false;
            } else {
                std::set<int> next;
                for (int r : inter) {
                    if (sets[id].find(r) != sets[id].end()) next.insert(r);
                }
                inter = next;
            }
            for (int r : sets[id]) uni.insert(r);
        }
        c.runsTogether = static_cast<int>(inter.size());
        c.runsTotal = static_cast<int>(uni.size());
        // Majority cause over members' classified last failures.
        std::map<std::string, int> votes;
        std::map<std::string, double> confSum;
        for (const std::string& id : c.members) {
            double rate = 0.0;
            auto tc = totalCount.find(id);
            auto fc = failCount.find(id);
            if (tc != totalCount.end() && tc->second > 0 && fc != failCount.end()) {
                rate = static_cast<double>(fc->second) / tc->second;
            }
            Cause cause = classifyFailure(lastMsg[id], rate);
            votes[cause.category]++;
            confSum[cause.category] += cause.confidence;
        }
        int best = -1;
        for (const auto& v : votes) {
            if (v.second > best ||
                (v.second == best && v.first < c.cause)) {  // alphabetical tie-break
                best = v.second;
                c.cause = v.first;
            }
        }
        c.confidence = best > 0 ? confSum[c.cause] / best : 0.0;
        c.confidence = std::round(c.confidence * 100.0) / 100.0;  // stable JSON output
        out.push_back(c);
    }
    std::sort(out.begin(), out.end(), [](const Cluster& a, const Cluster& b) {
        if (a.members.size() != b.members.size()) return a.members.size() > b.members.size();
        return a.members.front() < b.members.front();
    });
    return out;
}

}  // namespace tg
