#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <peerfs/core.hpp>

namespace peerfs {
namespace {

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


} // namespace
} // namespace peerfs

int main() {
    try {
        peerfs::pathTests();
        std::cout << "Path suite passed.\n";
        return 0;
    } catch (const std::exception &ERROR) {
        std::cerr << "FAIL: " << ERROR.what() << '\n';
        return 1;
    }
}
