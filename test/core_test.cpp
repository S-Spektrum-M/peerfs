#include <unistd.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>

#include <yaml-cpp/yaml.h>

#include <peerfs/core.hpp>

namespace peerfs {
namespace {

constexpr std::size_t PROPERTY_ITERATIONS = 1000;
constexpr unsigned RANDOM_SEED = 183745;
constexpr std::string_view RULES = R"(homelab:
  exports:
    - name: media
      path: /share
      grant: { laptop: rw, phone: r }
    - name: notes
      path: /home/user/share
      grant: { laptop: rw }
)";

void check(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

Path path(std::string_view text) {
    auto value = Path::parse(text);
    peerfs::check(value.has_value(), "test path should parse");
    return *value;
}

Topology topology(std::string_view text = "{}") {
    auto value = peerfs::parseTopology(text, "/home/alice");
    peerfs::check(value.has_value(), "test topology should parse");
    return *value;
}

std::vector<Export> rules() {
    auto value = peerfs::parseRules(RULES);
    peerfs::check(value.has_value(), "README rules should parse");
    return *value;
}

std::expected<Path, std::string> verifiedRoot(const Export &export_rule) {
    return export_rule.path;
}

bool hasIssue(const Plan &plan, std::string_view check) {
    for (const auto &ISSUE : plan.issues) {
        if (ISSUE.check == check) {
            return true;
        }
    }
    return false;
}

void pathTests() {
    peerfs::check(peerfs::path("/").contains(peerfs::path("/a")), "root contains every absolute path");
    peerfs::check(peerfs::path("/share").contains(peerfs::path("/share/a")), "component descendant");
    peerfs::check(!peerfs::path("/share").contains(peerfs::path("/shared")), "not character-prefix containment");
    peerfs::check(peerfs::path("//a/./b/../c/").string() == "/a/c", "lexical normalization");
    peerfs::check(peerfs::path("/a/../").string() == "/", "root normalization");
    peerfs::check(!Path::parse("/../../secret"), "above-root traversal rejected");
    peerfs::check(!Path::parse("relative"), "relative paths rejected");
    peerfs::check(!Path::parse(""), "empty path rejected");
    peerfs::check(!Path::parse(std::string("/a\0b", 4)), "embedded NUL rejected");
    peerfs::check(!Path::parse("~/data"), "never expand authority home implicitly");
    peerfs::check(!Path::parse("~bob/data", "/home/alice"), "named home expansion rejected");
    peerfs::check(Path::parse("~/Media", "/home/alice")->string() == "/home/alice/Media", "device home expansion");
    peerfs::check(Path::parse("~", "/home/alice")->string() == "/home/alice", "bare home expansion");
    peerfs::check(!peerfs::path("/").child(".."), "unsafe child rejected");
    peerfs::check(!peerfs::path("/").child("x/y"), "multicomponent child rejected");
}

void parserTests() {
    peerfs::check(peerfs::parseNode("{}")->ceiling.empty(), "default ceiling is deny all");
    peerfs::check(peerfs::parseNode("ceiling: []")->ceiling.empty(), "explicit empty ceiling");
    peerfs::check(peerfs::parseTopology("{}")->root.string() == "/mnt/peerfs", "default root");
    peerfs::check(Topology{}.root.string() == "/mnt/peerfs", "programmatic default topology root");
    peerfs::check(peerfs::parseRules("{}")->empty(), "empty rules allowed");
    constexpr std::array BAD_NODES = {"",
                                      "null",
                                      "[]",
                                      "ceiling: /share",
                                      "ceiling: [relative]",
                                      "ceiling: [~]",
                                      "typo: []",
                                      "ceiling: []\nceiling: []",
                                      "{}\n---\n{}"};
    for (auto text : BAD_NODES) {
        peerfs::check(!peerfs::parseNode(text), std::string("bad node accepted: ") + text);
    }
    constexpr std::array BAD_TOPOLOGIES = {"root: relative",
                                           "mounts: []",
                                           "mounts: {x: /a, x: /b}",
                                           "mounts: {../x: /a}",
                                           "mounts: {x: null}",
                                           "root: /a\ntypo: /b",
                                           "root: /a\nroot: /b",
                                           "mounts: &self {x: *self}"};
    for (auto text : BAD_TOPOLOGIES) {
        peerfs::check(!peerfs::parseTopology(text), std::string("bad topology accepted: ") + text);
    }
    constexpr std::array BAD_RULES = {"node: {}",
                                      "node: {exports: {}}",
                                      "node: {exports: [{name: x, path: /a}]}",
                                      "node: {exports: [{name: x, path: /a, grant: {laptop: write}}]}",
                                      "node: {exports: [{name: x, path: /a, grant: {laptop: r, laptop: rw}}]}",
                                      "node: {exports: [{name: x, path: /a, grant: {}, typo: 1}]}",
                                      "node: {exports: [{name: ../x, path: /a, grant: {}}]}",
                                      "node: {exports: [{name: x, path: /a, grant: null}]}",
                                      "node: {exports: [{name: x, name: y, path: /a, grant: {}}]}",
                                      "node: {exports: [{name: x, path: /a, grant: {}}]}\nnode: {exports: []}",
                                      "? [a, b]\n: {}",
                                      "node: {exports: ["};
    for (auto text : BAD_RULES) {
        peerfs::check(!peerfs::parseRules(text), std::string("bad rules accepted: ") + text);
    }
    std::string oversized(1024 * 1024 + 1, ' ');
    peerfs::check(!peerfs::parseRules(oversized), "input size bounded");
    std::string nested = "ceiling: ";
    constexpr std::size_t EXCESSIVE_DEPTH = 64;
    nested.append(EXCESSIVE_DEPTH, '[');
    nested += 'x';
    nested.append(EXCESSIVE_DEPTH, ']');
    peerfs::check(!peerfs::parseNode(nested), "nesting bounded");
    peerfs::check(!peerfs::parseNode("ceiling: &x [*x]"), "recursive alias traversal bounded");
    std::string too_many_nodes = "ceiling: [";
    constexpr std::size_t EXCESSIVE_NODES = 20001;
    for (std::size_t index = 0; index < EXCESSIVE_NODES; ++index) {
        too_many_nodes += "/a,";
    }
    too_many_nodes += ']';
    peerfs::check(!peerfs::parseNode(too_many_nodes), "expanded node traversal bounded");
    // Noncyclic YAML aliases are allowed, but are subject to the same limits.
    peerfs::check(peerfs::parseNode("ceiling: [&x /share, *x]").has_value(), "bounded scalar aliases");
}

void exampleTests() {
    auto exports = peerfs::rules();
    auto laptop_topology = peerfs::topology("root: /mnt/peerfs\nmounts: {media: ~/Media}");
    auto laptop = peerfs::compilePlan(exports, "laptop", laptop_topology, peerfs::verifiedRoot);
    peerfs::check(laptop.valid() && !laptop.stale, "fresh laptop plan");
    peerfs::check(laptop.entries.size() == 2, "laptop has two entries");
    peerfs::check(laptop.entries[0].target.string() == "/home/alice/Media", "media custom placement");
    peerfs::check(laptop.entries[1].target.string() == "/mnt/peerfs/notes", "notes default placement");
    peerfs::check(laptop.entries[0].mode == Mode::ReadWrite && laptop.entries[1].mode == Mode::ReadWrite,
                  "laptop exact modes");
    auto phone = peerfs::compilePlan(exports, "phone", peerfs::topology(), peerfs::verifiedRoot);
    peerfs::check(phone.valid() && !phone.stale && phone.entries.size() == 1, "phone fresh default topology");
    peerfs::check(phone.entries[0].target.string() == "/mnt/peerfs/media" && phone.entries[0].mode == Mode::Read,
                  "phone target and mode");
    auto stale = peerfs::compilePlan(exports, "phone", std::nullopt, peerfs::verifiedRoot);
    peerfs::check(stale.valid() && stale.stale, "absent topology is stale");
    auto ungranted = peerfs::compilePlan(exports, "stranger", peerfs::topology(), peerfs::verifiedRoot);
    peerfs::check(ungranted.valid() && ungranted.entries.empty(), "no implicit grants");
    auto encoded = YAML::Load(peerfs::renderPlan(laptop));
    peerfs::check(encoded["valid"].as<bool>() && !encoded["stale"].as<bool>(), "YAML flags");
    peerfs::check(encoded["entries"][0]["source"].as<std::string>() == "homelab:/share", "YAML source");
}

void preflightTests() {
    auto exports = peerfs::rules();
    auto duplicate = exports.front();
    duplicate.owner = "other";
    duplicate.grants.clear();
    exports.push_back(duplicate);
    auto laptop = peerfs::compilePlan(exports, "laptop", peerfs::topology(), peerfs::verifiedRoot);
    peerfs::check(peerfs::hasIssue(laptop, "PF1"), "PF1 sees duplicate even if other export is not granted");
    auto stranger = peerfs::compilePlan(exports, "stranger", peerfs::topology(), peerfs::verifiedRoot);
    peerfs::check(stranger.valid(), "PF1 isolation");

    exports = peerfs::rules();
    auto denied_notes = [](const Export &export_rule) -> std::expected<Path, std::string> {
        if (export_rule.name == "notes") {
            return std::unexpected("owner refused");
        }
        return export_rule.path;
    };
    laptop = peerfs::compilePlan(exports, "laptop", peerfs::topology(), denied_notes);
    auto phone = peerfs::compilePlan(exports, "phone", peerfs::topology(), denied_notes);
    peerfs::check(peerfs::hasIssue(laptop, "PF2") && phone.valid(), "PF2 refusal isolation");
    laptop = peerfs::compilePlan(exports, "laptop", peerfs::topology(), {});
    peerfs::check(!laptop.valid() && peerfs::hasIssue(laptop, "PF2"), "missing owner check fails closed");

    phone = peerfs::compilePlan(exports, "phone", peerfs::topology("mounts: {notes: /notes}"), peerfs::verifiedRoot);
    peerfs::check(peerfs::hasIssue(phone, "PF3") && phone.entries.size() == 1, "topology cannot add grants");
    laptop = peerfs::compilePlan(
        exports, "laptop", peerfs::topology("mounts: {media: /same, notes: /same}"), peerfs::verifiedRoot);
    peerfs::check(peerfs::hasIssue(laptop, "PF4"), "equal explicit targets");
    laptop = peerfs::compilePlan(
        exports, "laptop", peerfs::topology("mounts: {media: /same, notes: /same/nested}"), peerfs::verifiedRoot);
    peerfs::check(peerfs::hasIssue(laptop, "PF4"), "nested explicit targets");
    laptop = peerfs::compilePlan(
        exports, "laptop", peerfs::topology("mounts: {media: /mnt/peerfs/notes/inside}"), peerfs::verifiedRoot);
    peerfs::check(peerfs::hasIssue(laptop, "PF4"), "default and explicit target collision");
    laptop = peerfs::compilePlan(
        exports, "laptop", peerfs::topology("mounts: {media: /share, notes: /shared}"), peerfs::verifiedRoot);
    peerfs::check(laptop.valid(), "targets compare components");

    exports[1].path = peerfs::path("/share/notes");
    phone = peerfs::compilePlan(exports, "phone", peerfs::topology(), peerfs::verifiedRoot);
    peerfs::check(peerfs::hasIssue(phone, "PF5"), "nested same-owner roots forbidden even if other is ungranted");
    exports[1].path = exports[0].path;
    phone = peerfs::compilePlan(exports, "phone", peerfs::topology(), peerfs::verifiedRoot);
    peerfs::check(peerfs::hasIssue(phone, "PF5"), "identical same-owner roots forbidden");
    exports[1].owner = "other";
    laptop = peerfs::compilePlan(exports, "laptop", peerfs::topology(), peerfs::verifiedRoot);
    peerfs::check(laptop.valid(), "different owners may use identical paths");
    exports = peerfs::rules();
    auto alias_roots = [](const Export &) -> std::expected<Path, std::string> { return peerfs::path("/canonical"); };
    phone = peerfs::compilePlan(exports, "phone", peerfs::topology(), alias_roots);
    peerfs::check(peerfs::hasIssue(phone, "PF5"), "canonical aliases forbidden");
    stranger = peerfs::compilePlan(exports, "stranger", peerfs::topology(), alias_roots);
    peerfs::check(stranger.valid(), "PF5 isolation");
    std::size_t callbacks = 0;
    auto counting_check = [&callbacks](const Export &export_rule) -> std::expected<Path, std::string> {
        ++callbacks;
        return export_rule.path;
    };
    phone = peerfs::compilePlan(exports, "phone", peerfs::topology(), counting_check);
    peerfs::check(callbacks == exports.size(), "owner check runs exactly once per export, including ungranted roots");
    phone = peerfs::compilePlan(exports, "phone", peerfs::topology(), alias_roots);
    auto encoded = YAML::Load(peerfs::renderPlan(phone));
    peerfs::check(!encoded["valid"].as<bool>() && encoded["issues"][0]["check"].as<std::string>() == "PF5",
                  "structured refusal serialization");
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() / "peerfs-test-XXXXXX").string();
        auto directory = ::mkdtemp(pattern.data());
        if (!directory) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = directory;
    }
    TemporaryDirectory(const TemporaryDirectory &) = delete;
    TemporaryDirectory(TemporaryDirectory &&) = delete;
    TemporaryDirectory &operator=(const TemporaryDirectory &) = delete;
    TemporaryDirectory &operator=(TemporaryDirectory &&) = delete;
    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(root, error);
    }
    std::filesystem::path root;
};

void filesystemTests() {
    namespace fs = std::filesystem;
    TemporaryDirectory temporary;
    auto share = temporary.root / "share";
    auto outside = temporary.root / "shared";
    fs::create_directories(share / "inside");
    fs::create_directory(outside);
    fs::create_directory_symlink(outside, share / "escape");
    fs::create_directory_symlink(share / "inside", temporary.root / "alias");
    fs::create_symlink(temporary.root / "missing", share / "dangling");
    fs::create_symlink(share / "loop", share / "loop");
    Export export_rule;
    export_rule.path = peerfs::path((share / "inside").string());
    Node node;
    node.ceiling.push_back(peerfs::path(share.string()));
    peerfs::check(peerfs::checkLocalExport(export_rule, node).has_value(), "local contained root accepted");
    export_rule.path = peerfs::path((share / "escape").string());
    peerfs::check(!peerfs::checkLocalExport(export_rule, node), "symlink root escape refused");
    export_rule.path = peerfs::path(outside.string());
    peerfs::check(!peerfs::checkLocalExport(export_rule, node), "character prefix ceiling escape refused");
    export_rule.path = peerfs::path((temporary.root / "alias").string());
    auto alias = peerfs::checkLocalExport(export_rule, node);
    peerfs::check(alias && *alias == peerfs::path((share / "inside").string()), "canonical root returned");
    peerfs::check(!peerfs::checkLocalExport(export_rule, Node{}), "default empty ceiling denies");
    for (auto name : {"missing", "dangling", "loop"}) {
        export_rule.path = peerfs::path((share / name).string());
        peerfs::check(!peerfs::checkLocalExport(export_rule, node), "nonexistent/dangling/loop root refused");
    }
    auto file = share / "file.yaml";
    std::ofstream(file) << "ceiling: []\n";
    export_rule.path = peerfs::path(file.string());
    peerfs::check(!peerfs::checkLocalExport(export_rule, node), "regular file export root refused");
    auto loaded = peerfs::loadConfig(file.string());
    peerfs::check(loaded && *loaded == "ceiling: []\n", "YAML loader");
    peerfs::check(!peerfs::loadConfig((share / "missing.yaml").string()), "missing config error");
    peerfs::check(!peerfs::loadConfig(""), "empty filename error");
    peerfs::check(!peerfs::loadConfig(std::string("a\0b", 3)), "NUL filename error");
    std::ofstream(file) << std::string(1024 * 1024 + 1, ' ');
    peerfs::check(!peerfs::loadConfig(file.string()), "bounded file loader");
}

void propertyTests() {
    std::mt19937 random(RANDOM_SEED);
    auto exports = peerfs::rules();
    for (std::size_t iteration = 0; iteration < PROPERTY_ITERATIONS; ++iteration) {
        auto placement = peerfs::topology();
        auto suffix = std::to_string(random());
        placement.root = peerfs::path("/root-" + suffix);
        placement.mounts.emplace("media", peerfs::path("/media-" + suffix));
        auto laptop = peerfs::compilePlan(exports, "laptop", placement, peerfs::verifiedRoot);
        peerfs::check(laptop.valid() && laptop.entries.size() == exports.size(), "generated valid plan");
        for (std::size_t index = 0; index < exports.size(); ++index) {
            const auto &RULE = exports[index];
            const auto &ENTRY = laptop.entries[index];
            peerfs::check(ENTRY.name == RULE.name && ENTRY.owner == RULE.owner && ENTRY.source == RULE.path
                              && ENTRY.mode == RULE.grants.at("laptop"),
                          "grant faithfulness under arbitrary topology");
            auto descendant = ENTRY.target.child("child");
            peerfs::check(descendant.has_value(), "child path");
            std::size_t matches = 0;
            for (const auto &CANDIDATE : laptop.entries) {
                matches += CANDIDATE.target.contains(*descendant) ? 1 : 0;
            }
            peerfs::check(matches == 1, "unambiguous namespace resolution");
        }
        auto phone_before = peerfs::compilePlan(exports, "phone", peerfs::topology(), peerfs::verifiedRoot);
        placement.mounts.emplace("not-granted", peerfs::path("/invalid"));
        auto bad_laptop = peerfs::compilePlan(exports, "laptop", placement, peerfs::verifiedRoot);
        auto phone_after = peerfs::compilePlan(exports, "phone", peerfs::topology(), peerfs::verifiedRoot);
        peerfs::check(!bad_laptop.valid() && peerfs::renderPlan(phone_before) == peerfs::renderPlan(phone_after),
                      "topology failure isolation");
        auto ancestor = peerfs::path("/a/" + suffix);
        auto child = ancestor.child("x");
        auto grandchild = child->child("y");
        peerfs::check(ancestor.contains(ancestor) && ancestor.contains(*child) && ancestor.contains(*grandchild)
                          && !child->contains(ancestor),
                      "component prefix partial order and transitivity");
    }
}

} // namespace
} // namespace peerfs

int main() {
    try {
        peerfs::pathTests();
        peerfs::parserTests();
        peerfs::exampleTests();
        peerfs::preflightTests();
        peerfs::filesystemTests();
        peerfs::propertyTests();
        std::cout << "All 6 suites passed (including 1000 deterministic property iterations).\n";
        return 0;
    } catch (const std::exception &ERROR) {
        std::cerr << "FAIL: " << ERROR.what() << '\n';
        return 1;
    }
}
