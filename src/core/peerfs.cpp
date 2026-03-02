#include <filesystem>
#include <utility>

#include <yaml-cpp/yaml.h>

#include <peerfs/core.hpp>

namespace peerfs {

Plan compilePlan(std::span<const Export> rules,
                 std::string_view device,
                 const std::optional<Topology> &topology,
                 const OwnerCheck &owner_check) {
    Plan result;
    result.device = device;
    result.stale = !topology.has_value();
    auto placement = topology.value_or(Topology{});
    std::vector<std::expected<Path, std::string>> roots;
    roots.reserve(rules.size());
    // Evaluate once per export, including ungranted exports, so canonical aliases
    // cannot hide an overlap with a different grant. Results are never cached.
    for (const auto &RULE : rules) {
        roots.push_back(owner_check ? owner_check(RULE) : std::unexpected(std::string("owner check unavailable")));
    }
    for (std::size_t index = 0; index < rules.size(); ++index) {
        const auto &RULE = rules[index];
        auto grant = RULE.grants.find(std::string(device));
        if (grant == RULE.grants.end()) {
            continue;
        }
        auto target = placement.root.child(RULE.name);
        if (auto explicit_target = placement.mounts.find(RULE.name); explicit_target != placement.mounts.end()) {
            target = explicit_target->second;
        }
        if (!target) {
            result.issues.push_back({"CONFIG", RULE.name, target.error()});
            continue;
        }
        result.entries.push_back({RULE.name, RULE.owner, RULE.path, *target, grant->second});
        if (!roots[index]) {
            result.issues.push_back({"PF2", RULE.name, roots[index].error()});
        }
        for (std::size_t other = 0; other < rules.size(); ++other) {
            if (index == other) {
                continue;
            }
            const auto &OTHER = rules[other];
            if (RULE.name == OTHER.name) {
                result.issues.push_back({"PF1", RULE.name, "duplicate export name (also on " + OTHER.owner + ")"});
            }
            if (RULE.owner != OTHER.owner) {
                continue;
            }
            const bool LEXICAL_OVERLAP = RULE.path.contains(OTHER.path) || OTHER.path.contains(RULE.path);
            const bool CANONICAL_OVERLAP =
                roots[index] && roots[other]
                && (roots[index]->contains(*roots[other]) || roots[other]->contains(*roots[index]));
            if (LEXICAL_OVERLAP || CANONICAL_OVERLAP) {
                result.issues.push_back({"PF5", RULE.name, "overlaps same-owner export " + OTHER.name});
            }
        }
    }
    for (const auto &[NAME, TARGET] : placement.mounts) {
        bool granted = false;
        for (const auto &RULE : rules) {
            granted = granted || (RULE.name == NAME && RULE.grants.contains(std::string(device)));
        }
        if (!granted) {
            result.issues.push_back({"PF3", NAME, "topology places an export not granted to this device"});
        }
    }
    for (std::size_t index = 0; index < result.entries.size(); ++index) {
        for (std::size_t other = index + 1; other < result.entries.size(); ++other) {
            const auto &LEFT = result.entries[index];
            const auto &RIGHT = result.entries[other];
            if (LEFT.target.contains(RIGHT.target) || RIGHT.target.contains(LEFT.target)) {
                result.issues.push_back(
                    {"PF4", LEFT.name, "target collides with or contains/is contained by " + RIGHT.name});
            }
        }
    }
    return result;
}

std::expected<Path, std::string> checkLocalExport(const Export &export_rule, const Node &node) {
    namespace fs = std::filesystem;
    std::error_code error;
    auto canonical = fs::canonical(export_rule.path.string(), error);
    if (error) {
        return std::unexpected("cannot resolve export directory: " + error.message());
    }
    if (!fs::is_directory(canonical, error) || error) {
        return std::unexpected("export root is not an accessible directory");
    }
    auto root = Path::parse(canonical.generic_string());
    if (!root) {
        return root;
    }
    for (const auto &CEILING : node.ceiling) {
        auto resolved_ceiling = fs::canonical(CEILING.string(), error);
        if (error || !fs::is_directory(resolved_ceiling, error) || error) {
            continue;
        }
        auto ceiling = Path::parse(resolved_ceiling.generic_string());
        if (ceiling && ceiling->contains(*root)) {
            return root;
        }
    }
    return std::unexpected("canonical export root is outside the owner's ceiling (or no ceiling directory resolves)");
}

std::string renderPlan(const Plan &plan) {
    YAML::Emitter output;
    output << YAML::BeginMap << YAML::Key << "device" << YAML::Value << plan.device;
    output << YAML::Key << "valid" << YAML::Value << plan.valid();
    output << YAML::Key << "stale" << YAML::Value << plan.stale;
    output << YAML::Key << "entries" << YAML::Value << YAML::BeginSeq;
    for (const auto &ENTRY : plan.entries) {
        output << YAML::BeginMap << YAML::Key << "export" << YAML::Value << ENTRY.name;
        output << YAML::Key << "source" << YAML::Value << (ENTRY.owner + ":" + ENTRY.source.string());
        output << YAML::Key << "target" << YAML::Value << ENTRY.target.string();
        output << YAML::Key << "mode" << YAML::Value << (ENTRY.mode == Mode::Read ? "r" : "rw") << YAML::EndMap;
    }
    output << YAML::EndSeq << YAML::Key << "issues" << YAML::Value << YAML::BeginSeq;
    for (const auto &ISSUE : plan.issues) {
        output << YAML::BeginMap << YAML::Key << "check" << YAML::Value << ISSUE.check;
        output << YAML::Key << "export" << YAML::Value << ISSUE.export_name;
        output << YAML::Key << "message" << YAML::Value << ISSUE.message << YAML::EndMap;
    }
    output << YAML::EndSeq << YAML::EndMap;
    return std::string(output.c_str()) + '\n';
}

} // namespace peerfs
