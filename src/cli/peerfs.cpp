#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include <peerfs/core.hpp>
#include <peerfs/live.hpp>

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

Live read-only commands (foreground):
  peerfs authority --network FILE --rules FILE --state /absolute/private/directory
  peerfs export --network FILE --node FILE
  peerfs status --network FILE
  peerfs admit --network FILE --topology FILE [--home /device/home]
  peerfs mount --network FILE --topology FILE --export NAME [--home /device/home]
Live commands authenticate through the local tailscaled socket and enrolled StableIDs.
Each mount process handles one export; use fusermount3 -u TARGET to unmount.
)";

} // namespace
} // namespace peerfs

int main(int argc, char **argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << peerfs::USAGE;
        return 0;
    }
    if (argc >= 2
        && (std::string_view(argv[1]) == "authority" || std::string_view(argv[1]) == "export"
            || std::string_view(argv[1]) == "admit" || std::string_view(argv[1]) == "mount"
            || std::string_view(argv[1]) == "status")) {
        std::string command = argv[1];
        std::map<std::string, std::string> arguments;
        for (int index = 2; index < argc; ++index) {
            std::string key = argv[index];
            bool allowed = key == "--network" || (command == "authority" && (key == "--rules" || key == "--state"))
                           || (command == "export" && key == "--node")
                           || ((command == "admit" || command == "mount") && (key == "--topology" || key == "--home"))
                           || (command == "mount" && key == "--export");
            if (!allowed || ++index >= argc || !arguments.emplace(key, argv[index]).second) {
                std::cerr << "invalid, missing or duplicate live-command argument\n" << peerfs::USAGE;
                return peerfs::INPUT_ERROR;
            }
        }
        bool complete = arguments.contains("--network")
                        && (command != "authority" || (arguments.contains("--rules") && arguments.contains("--state")))
                        && (command != "export" || arguments.contains("--node"))
                        && ((command != "admit" && command != "mount") || arguments.contains("--topology"))
                        && (command != "mount" || arguments.contains("--export"));
        if (!complete) {
            std::cerr << peerfs::USAGE;
            return peerfs::INPUT_ERROR;
        }
        if (command == "admit" || command == "status") {
            auto response =
                command == "status"
                    ? peerfs::authorityStatus(arguments["--network"])
                    : peerfs::admitDevice(arguments["--network"], arguments["--topology"], arguments["--home"]);
            if (!response) {
                std::cerr << response.error() << '\n';
                return peerfs::INPUT_ERROR;
            }
            std::cout << *response;
            return command == "status" || nlohmann::json::parse(*response).at("admitted").get<bool>()
                       ? 0
                       : peerfs::INVALID_PLAN;
        }
        auto result =
            command == "authority"
                ? peerfs::serveAuthority(arguments["--network"], arguments["--rules"], arguments["--state"])
            : command == "export"
                ? peerfs::serveExporter(arguments["--network"], arguments["--node"])
                : peerfs::mountExport(
                      arguments["--network"], arguments["--topology"], arguments["--home"], arguments["--export"]);
        if (!result) {
            std::cerr << result.error() << '\n';
            return peerfs::INPUT_ERROR;
        }
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
