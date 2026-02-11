#include <cstddef>
#include <set>
#include <stdexcept>
#include <utility>

#include <yaml-cpp/yaml.h>

#include <peerfs/core.hpp>

namespace peerfs {
namespace {

constexpr std::size_t MAX_CONFIG_BYTES = 1024 * 1024;
constexpr std::size_t MAX_NODES = 20000;
constexpr std::size_t MAX_DEPTH = 32;

// yaml-cpp reports expected parse failures as exceptions. Keep that convention
// inside this translation unit and translate once at the public boundary.
class SchemaError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

void validateTree(const YAML::Node &node, std::size_t depth, std::size_t &remaining) {
    if (depth > MAX_DEPTH || remaining == 0) {
        throw SchemaError("configuration exceeds nesting or node limit (possibly recursive aliases)");
    }
    --remaining;
    if (node.IsMap()) {
        std::set<std::string> keys;
        for (const auto &PAIR : node) {
            if (!PAIR.first.IsScalar()) {
                throw SchemaError("mapping keys must be strings");
            }
            auto key = PAIR.first.Scalar();
            if (!keys.insert(key).second) {
                throw SchemaError("duplicate mapping key: " + key);
            }
            peerfs::validateTree(PAIR.second, depth + 1, remaining);
        }
    } else if (node.IsSequence()) {
        for (const auto &ITEM : node) {
            peerfs::validateTree(ITEM, depth + 1, remaining);
        }
    }
}

YAML::Node document(std::string_view text) {
    if (text.size() > MAX_CONFIG_BYTES) {
        throw SchemaError("configuration exceeds 1 MiB limit");
    }
    auto documents = YAML::LoadAll(std::string(text));
    if (documents.size() != 1) {
        throw SchemaError("expected exactly one YAML document");
    }
    auto remaining = MAX_NODES;
    peerfs::validateTree(documents.front(), 0, remaining);
    return documents.front();
}

void mapping(const YAML::Node &node, std::string_view context) {
    if (!node.IsMap()) {
        throw SchemaError(std::string(context) + " must be a mapping");
    }
}

void fields(const YAML::Node &node, std::initializer_list<std::string_view> allowed, std::string_view context) {
    peerfs::mapping(node, context);
    for (const auto &PAIR : node) {
        auto key = PAIR.first.Scalar();
        bool found = false;
        for (auto candidate : allowed) {
            found = found || candidate == key;
        }
        if (!found) {
            throw SchemaError(std::string(context) + ": unknown field " + key);
        }
    }
}

std::string scalar(const YAML::Node &node, std::string_view context) {
    if (!node.IsScalar()) {
        throw SchemaError(std::string(context) + " must be a scalar string");
    }
    return node.Scalar();
}

std::string identifier(const YAML::Node &node, std::string_view context) {
    auto value = peerfs::scalar(node, context);
    const auto alnum = [](unsigned char character) -> bool {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
               || (character >= '0' && character <= '9');
    };
    if (value.empty() || !alnum(static_cast<unsigned char>(value.front()))) {
        throw SchemaError(std::string(context) + " must begin with an ASCII letter or digit");
    }
    for (auto character : value) {
        if (!alnum(static_cast<unsigned char>(character)) && character != '_' && character != '-' && character != '.') {
            throw SchemaError(std::string(context) + " must contain only ASCII letters, digits, _, - or .");
        }
    }
    return value;
}

Path path(const YAML::Node &node, std::string_view context, std::string_view home = {}) {
    auto result = Path::parse(peerfs::scalar(node, context), home);
    if (!result) {
        throw SchemaError(std::string(context) + ": " + result.error());
    }
    return *result;
}

} // namespace

std::expected<Node, std::string> parseNode(std::string_view yaml) {
    try {
        auto doc = peerfs::document(yaml);
        peerfs::fields(doc, {"ceiling"}, "node");
        Node result;
        if (auto ceiling = doc["ceiling"]) {
            if (!ceiling.IsSequence()) {
                throw SchemaError("ceiling must be a sequence");
            }
            for (const auto &ITEM : ceiling) {
                result.ceiling.push_back(peerfs::path(ITEM, "ceiling path"));
            }
        }
        return result;
    } catch (const YAML::Exception &ERROR) {
        return std::unexpected(ERROR.what());
    } catch (const SchemaError &ERROR) {
        return std::unexpected(ERROR.what());
    }
}

std::expected<Topology, std::string> parseTopology(std::string_view yaml, std::string_view home) {
    try {
        auto doc = peerfs::document(yaml);
        peerfs::fields(doc, {"root", "mounts"}, "topology");
        Topology result;
        result.root = doc["root"] ? peerfs::path(doc["root"], "root", home) : *Path::parse("/mnt/peerfs");
        if (auto mounts = doc["mounts"]) {
            peerfs::mapping(mounts, "mounts");
            for (const auto &PAIR : mounts) {
                result.mounts.emplace(peerfs::identifier(PAIR.first, "export name"),
                                      peerfs::path(PAIR.second, "mount target", home));
            }
        }
        return result;
    } catch (const YAML::Exception &ERROR) {
        return std::unexpected(ERROR.what());
    } catch (const SchemaError &ERROR) {
        return std::unexpected(ERROR.what());
    }
}

std::expected<std::vector<Export>, std::string> parseRules(std::string_view yaml) {
    try {
        auto doc = peerfs::document(yaml);
        peerfs::mapping(doc, "rules");
        std::vector<Export> result;
        for (const auto &OWNER : doc) {
            auto owner = peerfs::identifier(OWNER.first, "owner");
            peerfs::fields(OWNER.second, {"exports"}, "owner");
            auto exports = OWNER.second["exports"];
            if (!exports.IsSequence()) {
                throw SchemaError("exports must be a sequence");
            }
            for (const auto &ITEM : exports) {
                peerfs::fields(ITEM, {"name", "path", "grant"}, "export");
                Export export_rule;
                export_rule.owner = owner;
                export_rule.name = peerfs::identifier(ITEM["name"], "export name");
                export_rule.path = peerfs::path(ITEM["path"], "export path");
                auto grants = ITEM["grant"];
                peerfs::mapping(grants, "grant");
                for (const auto &PAIR : grants) {
                    auto device = peerfs::identifier(PAIR.first, "grantee");
                    auto mode = peerfs::scalar(PAIR.second, "mode");
                    if (mode != "r" && mode != "rw") {
                        throw SchemaError("grant mode must be r or rw");
                    }
                    export_rule.grants.emplace(device, mode == "r" ? Mode::Read : Mode::ReadWrite);
                }
                result.push_back(std::move(export_rule));
            }
        }
        return result;
    } catch (const YAML::Exception &ERROR) {
        return std::unexpected(ERROR.what());
    } catch (const SchemaError &ERROR) {
        return std::unexpected(ERROR.what());
    }
}

} // namespace peerfs
