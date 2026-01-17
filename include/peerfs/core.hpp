#pragma once

#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if !defined(__cpp_lib_expected) || __cpp_lib_expected < 202202L
#error "PeerFS requires C++23 std::expected"
#endif

namespace peerfs {

// Paths are absolute, lexically normalized component lists, never host-resolved.
class [[doc::brief("Absolute lexical path; containment compares whole components.")]] Path {
public:
    Path() = default;
    Path(const Path &) = default;
    Path(Path &&) noexcept = default;
    Path &operator=(const Path &) = default;
    Path &operator=(Path &&) noexcept = default;
    ~Path() = default;

    [[nodiscard, doc::brief("Parse an absolute path; expand only ~ and ~/ using an explicit device home.")]]
    static std::expected<Path, std::string> parse(std::string_view text, std::string_view home = {});
    [[nodiscard, doc::brief("Render the normalized absolute path.")]] std::string string() const;
    [[nodiscard, doc::brief("True if this path is a component-wise prefix of other.")]]
    bool contains(const Path &other) const;
    [[nodiscard, doc::brief("Append one safe export-name component.")]]
    std::expected<Path, std::string> child(std::string_view name) const;
    bool operator==(const Path &) const = default;

private:
    std::vector<std::string> components_;
};

enum class Mode { Read, ReadWrite };

struct [[doc::brief("An admin-declared export and exact per-device grants.")]] Export {
    std::string name;
    std::string owner;
    Path path;
    std::map<std::string, Mode> grants;
};

struct [[doc::brief("Owner-local maximum export region; empty means deny all.")]] Node {
    std::vector<Path> ceiling;
};

struct [[doc::brief("Device-local placement, never an access-control input.")]] Topology {
    Path root = *Path::parse("/mnt/peerfs");
    std::map<std::string, Path> mounts;
};

struct [[doc::brief("One generated mount binding.")]] Entry {
    std::string name;
    std::string owner;
    Path source;
    Path target;
    Mode mode = Mode::Read;
};

struct [[doc::brief("Pre-flight failure with stable PF identifier and affected export.")]] Issue {
    std::string check;
    std::string export_name;
    std::string message;
};

struct [[doc::brief("Compilation result; invalid or stale results are not mount admission.")]] Plan {
    std::string device;
    std::vector<Entry> entries;
    std::vector<Issue> issues;
    bool stale = false;
    [[nodiscard, doc::brief("Whether all checks passed (does not imply fresh admission).")]] bool valid() const;
};

} // namespace peerfs
