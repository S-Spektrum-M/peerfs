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


} // namespace
} // namespace peerfs

int main() {
    try {
        peerfs::pathTests();
        peerfs::parserTests();
        std::cout << "Path and parser suites passed.\n";
        return 0;
    } catch (const std::exception &ERROR) {
        std::cerr << "FAIL: " << ERROR.what() << '\n';
        return 1;
    }
}
