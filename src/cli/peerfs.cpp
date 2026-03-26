#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include <peerfs/core.hpp>

namespace peerfs {
namespace {

constexpr int INVALID_PLAN = 1;
constexpr int INPUT_ERROR = 2;
constexpr std::string_view USAGE =
    R"(Usage: peerfs plan --rules FILE --device NAME [--topology FILE] [--home /device/home]
                   [--node OWNER=FILE ...] [--local-owner OWNER | --preview]

Offline plan inspection only: this command never admits or mounts a device.
Without --topology, the default placement is used and the result is stale.
--local-owner checks only that owner's actual filesystem and node ceiling.
--preview checks lexical ceiling containment only; NOT security validation.
Other owners fail PF2 unless --preview is explicitly selected.
YAML and trusted .pkl inputs are supported. Pkl must be installed separately.
Exit: 0 valid inspection result, 1 refused plan, 2 usage/configuration error.
)";

} // namespace
} // namespace peerfs

int main(int argc, char **argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << peerfs::USAGE;
        return 0;
    }
    if (argc < 2 || std::string_view(argv[1]) != "plan") {
        std::cerr << peerfs::USAGE;
        return peerfs::INPUT_ERROR;
    }
    std::map<std::string, std::string> options;
    std::map<std::string, peerfs::Node> nodes;
    bool preview = false;
    for (int index = 2; index < argc; ++index) {
        std::string option = argv[index];
        if (option == "--preview") {
            if (preview) {
                std::cerr << "duplicate --preview\n";
                return peerfs::INPUT_ERROR;
            }
            preview = true;
            continue;
        }
        if (option != "--rules" && option != "--device" && option != "--topology" && option != "--home"
            && option != "--node" && option != "--local-owner") {
            std::cerr << "unknown option: " << option << '\n';
            return peerfs::INPUT_ERROR;
        }
        if (++index >= argc) {
            std::cerr << "missing value for " << option << '\n';
            return peerfs::INPUT_ERROR;
        }
        std::string value = argv[index];
        if (option == "--node") {
            auto separator = value.find('=');
            if (separator == std::string::npos || separator == 0 || separator + 1 == value.size()) {
                std::cerr << "--node requires OWNER=FILE\n";
                return peerfs::INPUT_ERROR;
            }
            auto text = peerfs::loadConfig(value.substr(separator + 1));
            if (!text) {
                std::cerr << text.error() << '\n';
                return peerfs::INPUT_ERROR;
            }
            auto node = peerfs::parseNode(*text);
            if (!node) {
                std::cerr << node.error() << '\n';
                return peerfs::INPUT_ERROR;
            }
            if (!nodes.emplace(value.substr(0, separator), *node).second) {
                std::cerr << "duplicate --node owner\n";
                return peerfs::INPUT_ERROR;
            }
        } else if (!options.emplace(option, value).second) {
            std::cerr << "duplicate option: " << option << '\n';
            return peerfs::INPUT_ERROR;
        }
    }
    if (!options.contains("--rules") || !options.contains("--device") || options["--device"].empty()
        || (preview && options.contains("--local-owner"))) {
        std::cerr << peerfs::USAGE;
        return peerfs::INPUT_ERROR;
    }
    auto text = peerfs::loadConfig(options["--rules"]);
    if (!text) {
        std::cerr << text.error() << '\n';
        return peerfs::INPUT_ERROR;
    }
    auto rules = peerfs::parseRules(*text);
    if (!rules) {
        std::cerr << rules.error() << '\n';
        return peerfs::INPUT_ERROR;
    }
    std::optional<peerfs::Topology> topology;
    if (options.contains("--topology")) {
        auto topology_text = peerfs::loadConfig(options["--topology"]);
        if (!topology_text) {
            std::cerr << topology_text.error() << '\n';
            return peerfs::INPUT_ERROR;
        }
        auto parsed = peerfs::parseTopology(*topology_text, options["--home"]);
        if (!parsed) {
            std::cerr << parsed.error() << '\n';
            return peerfs::INPUT_ERROR;
        }
        topology = *parsed;
    }
    auto owner_check =
        [&nodes, &options, preview](const peerfs::Export &export_rule) -> std::expected<peerfs::Path, std::string> {
        auto node = nodes.find(export_rule.owner);
        if (node == nodes.end()) {
            return std::unexpected("no owner-local ceiling supplied");
        }
        if (!preview) {
            if (!options.contains("--local-owner") || options.at("--local-owner") != export_rule.owner) {
                return std::unexpected("owner is not local; remote PF2 verification is unavailable in Phase 1");
            }
            return peerfs::checkLocalExport(export_rule, node->second);
        }
        for (const auto &CEILING : node->second.ceiling) {
            if (CEILING.contains(export_rule.path)) {
                return export_rule.path;
            }
        }
        return std::unexpected("lexical export path is outside the supplied ceiling");
    };
    auto plan = peerfs::compilePlan(*rules, options["--device"], topology, owner_check);
    std::cout << "admission: false\nvalidation: " << (preview ? "lexical-preview" : "local-owner-checks") << '\n';
    std::cout << peerfs::renderPlan(plan);
    return plan.valid() ? 0 : peerfs::INVALID_PLAN;
}
