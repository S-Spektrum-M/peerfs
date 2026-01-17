#include <algorithm>

#include <peerfs/core.hpp>

namespace peerfs {

std::expected<Path, std::string> Path::parse(std::string_view text, std::string_view home) {
    if (text.empty() || text.find('\0') != std::string_view::npos) {
        return std::unexpected("path must be nonempty and contain no NUL");
    }
    std::string expanded;
    if (text.front() == '~') {
        if (text != "~" && !text.starts_with("~/")) {
            return std::unexpected("only ~ and ~/ home expansion are supported");
        }
        if (home.empty() || home.front() != '/' || home.find('\0') != std::string_view::npos) {
            return std::unexpected("home expansion requires an explicit absolute device home");
        }
        expanded = std::string(home) + std::string(text.substr(1));
        text = expanded;
    }
    if (text.front() != '/') {
        return std::unexpected("path must be absolute");
    }
    Path result;
    std::size_t start = 1;
    while (start <= text.size()) {
        auto end = text.find('/', start);
        if (end == std::string_view::npos) {
            end = text.size();
        }
        auto part = text.substr(start, end - start);
        if (part == "..") {
            if (result.components_.empty()) {
                return std::unexpected("path traverses above root");
            }
            result.components_.pop_back();
        } else if (!part.empty() && part != ".") {
            result.components_.emplace_back(part);
        }
        start = end + 1;
    }
    return result;
}

std::string Path::string() const {
    std::string result;
    for (const auto &COMPONENT : components_) {
        result += '/' + COMPONENT;
    }
    return result.empty() ? "/" : result;
}

bool Path::contains(const Path &other) const {
    return components_.size() <= other.components_.size()
           && std::equal(components_.begin(), components_.end(), other.components_.begin());
}

std::expected<Path, std::string> Path::child(std::string_view name) const {
    if (name.empty() || name == "." || name == ".." || name.find('/') != std::string_view::npos
        || name.find('\0') != std::string_view::npos) {
        return std::unexpected("export name must be one nonempty path component other than . or ..");
    }
    Path result = *this;
    result.components_.emplace_back(name);
    return result;
}

bool Plan::valid() const {
    return issues.empty();
}

} // namespace peerfs
