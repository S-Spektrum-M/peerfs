#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <vector>

#include <linux/openat2.h>

#include "runtime.hpp"
#include <peerfs/live.hpp>

namespace peerfs::live {

std::string relativePath(std::string_view path) {
    if (path.empty()) {
        return ".";
    }
    if (path.front() == '/' || path.find('\0') != std::string_view::npos || path.size() > 4096) {
        throw Failure("expected an export-relative path", EACCES);
    }
    std::size_t start = 0;
    while (start <= path.size()) {
        auto end = path.find('/', start);
        if (end == std::string_view::npos) {
            end = path.size();
        }
        if (path.substr(start, end - start) == "..") {
            throw Failure("parent traversal is forbidden", EACCES);
        }
        start = end + 1;
    }
    return std::string(path);
}

Fd openBeneath(int root, std::string_view relative, std::uint64_t flags) {
    auto path = peerfs::live::relativePath(relative);
    open_how how{};
    how.flags = flags | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    int opened = static_cast<int>(::syscall(SYS_openat2, root, path.c_str(), &how, sizeof(how)));
    if (opened < 0) {
        auto code = errno;
        if (code == EXDEV || code == ELOOP) {
            code = EACCES;
        }
        if (code == ENOSYS) {
            throw Failure("openat2 is required; no unsafe fallback", ENOTSUP);
        }
        throw Failure("contained open refused: " + std::string(std::strerror(errno)), code);
    }
    return Fd(opened);
}

namespace {

struct Ceiling {
    Path path;
    Fd directory;
};
struct Root {
    std::string source;
    Path canonical;
    Fd directory;
    std::chrono::steady_clock::time_point expires;
};

Json metadata(const struct stat &value) {
    if (!S_ISREG(value.st_mode) && !S_ISDIR(value.st_mode)) {
        throw Failure("special files are not exported", ENOTSUP);
    }
    return Json{{"directory", S_ISDIR(value.st_mode)},
                {"size", value.st_size},
                {"inode", value.st_ino},
                {"mtime", value.st_mtim.tv_sec},
                {"mtime_ns", value.st_mtim.tv_nsec}};
}

class Exporter {
public:
    Exporter(const Network &network, std::string_view node_file) : network_(network) {
        if (::geteuid() == 0 || ::getuid() == 0) {
            throw Failure("exporter must run as a non-root user", EACCES);
        }
        auto node = peerfs::parseNode(peerfs::live::fileText(node_file));
        if (!node) {
            throw Failure(node.error(), EINVAL);
        }
        Fd filesystem_root(::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC));
        for (const auto &CEILING : node->ceiling) {
            // Resolve owner-authored ceilings once; pin the directory itself.
            // Thereafter no pathname rename can redirect that authority.
            std::error_code error;
            auto canonical = std::filesystem::canonical(CEILING.string(), error);
            if (error) {
                throw Failure("cannot resolve configured ceiling: " + error.message(), EACCES);
            }
            auto path = Path::parse(canonical.generic_string());
            if (!path) {
                throw Failure(path.error(), EINVAL);
            }
            auto relative = path->string().substr(1);
            open_how how{};
            how.flags = O_PATH | O_DIRECTORY | O_CLOEXEC;
            how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
            Fd pinned(static_cast<int>(::syscall(
                SYS_openat2, filesystem_root.get(), relative.empty() ? "." : relative.c_str(), &how, sizeof(how))));
            ceilings_.push_back(Ceiling{*path, std::move(pinned)});
        }
    }

    Json handle(std::string_view caller, const Json &body) {
        auto operation = peerfs::live::text(body, "op");
        if (operation == "verify") {
            return this->verify(caller, body);
        }
        if (operation != "stat" && operation != "open" && operation != "read" && operation != "readdir") {
            throw Failure("read-only service: unsupported operation", EROFS);
        }
        if (operation == "read") {
            peerfs::live::fields(body, {"op", "session", "export", "path", "offset", "size"});
        } else if (operation == "readdir") {
            peerfs::live::fields(body, {"op", "session", "export", "path", "offset"});
        } else {
            peerfs::live::fields(body, {"op", "session", "export", "path"});
        }
        auto name = peerfs::live::text(body, "export");
        auto relative = peerfs::live::relativePath(peerfs::live::text(body, "path"));
        // No cached authorization: only this exporter's authenticated identity may
        // ask the authority, and the grantee comes from this TCP connection's WhoIs.
        auto approved = peerfs::live::request(network_,
                                              network_.authority,
                                              Json{{"op", "authorize"},
                                                   {"session", peerfs::live::text(body, "session")},
                                                   {"export", name},
                                                   {"device", caller}},
                                              true);
        Fd directory;
        {
            std::lock_guard guard(mutex_);
            auto root = roots_.find(peerfs::live::text(approved, "handle"));
            if (root == roots_.end() || root->second.expires <= std::chrono::steady_clock::now()
                || root->second.source != peerfs::live::text(approved, "source")
                || root->second.canonical.string() != peerfs::live::text(approved, "root")) {
                throw Failure("owner root handle expired or lost; re-admission required", EACCES);
            }
            directory = Fd(::fcntl(root->second.directory.get(), F_DUPFD_CLOEXEC, 0));
        }
        auto file = peerfs::live::openBeneath(directory.get(), relative, O_PATH);
        struct stat info{};
        if (::fstat(file.get(), &info) < 0) {
            throw Failure("fstat failed", errno);
        }
        auto result = peerfs::live::metadata(info); // Reject devices/FIFOs/sockets BEFORE opening for read.
        result["ok"] = true;
        if (operation == "stat") {
            return result;
        }
        // Reopen our own pinned, type-checked descriptor, not the untrusted path.
        // /proc must be mounted; this deliberate internal magic-link is never user-controlled.
        auto proc_path = "/proc/self/fd/" + std::to_string(file.get());
        Fd readable(::open(proc_path.c_str(), O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC));
        if (operation == "open") {
            if (!S_ISREG(info.st_mode)) {
                throw Failure("not a regular file", EISDIR);
            }
            return result;
        }
        if (operation == "read") {
            if (!S_ISREG(info.st_mode)) {
                throw Failure("not a regular file", EISDIR);
            }
            auto offset = peerfs::live::number(body, "offset");
            auto size = peerfs::live::number(body, "size");
            if (size > MAX_READ || offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
                throw Failure("read bounds exceeded", EINVAL);
            }
            std::string data(static_cast<std::size_t>(size), '\0');
            ssize_t count = 0;
            do {
                count = ::pread(readable.get(), data.data(), data.size(), static_cast<off_t>(offset));
            } while (count < 0 && errno == EINTR);
            if (count < 0) {
                throw Failure("pread failed", errno);
            }
            data.resize(static_cast<std::size_t>(count));
            result["data"] = peerfs::live::encodeHex(data);
            return result;
        }
        if (!S_ISDIR(info.st_mode)) {
            throw Failure("not a directory", ENOTDIR);
        }
        auto raw_directory = ::fdopendir(readable.get());
        if (!raw_directory) {
            throw Failure("fdopendir failed", errno);
        }
        static_cast<void>(readable.release());
        auto close_directory = [](DIR *value) -> void { ::closedir(value); };
        std::unique_ptr<DIR, decltype(close_directory)> listing(raw_directory, close_directory);
        auto offset = peerfs::live::number(body, "offset");
        constexpr std::uint64_t MAX_DIRECTORY_OFFSET = 1000000;
        constexpr std::size_t DIRECTORY_PAGE = 128;
        if (offset > MAX_DIRECTORY_OFFSET) {
            throw Failure("directory offset limit exceeded", EOVERFLOW);
        }
        std::uint64_t index = 0;
        Json names = Json::array();
        // Entry kinds let clients skip a stat per entry; unknown/other kinds are
        // left for a later (authorized) stat to resolve or refuse.
        Json types = Json::array();
        bool end = false;
        while (names.size() < DIRECTORY_PAGE) {
            errno = 0;
            auto entry = ::readdir(listing.get());
            if (!entry) {
                if (errno != 0) {
                    throw Failure("readdir failed", errno);
                }
                end = true;
                break;
            }
            if (index++ < offset) {
                continue;
            }
            names.push_back(entry->d_name);
            types.push_back(entry->d_type == DT_DIR ? "d" : entry->d_type == DT_REG ? "f" : "");
        }
        result["names"] = names;
        result["types"] = types;
        result["next"] = index;
        result["end"] = end;
        return result;
    }

private:
    Json verify(std::string_view caller, const Json &body) {
        peerfs::live::fields(body, {"op", "export", "path"});
        if (caller != network_.authority) {
            throw Failure("only the authority may verify exports", EACCES);
        }
        auto source = peerfs::live::text(body, "path");
        auto declared = Path::parse(source);
        if (!declared || declared->string() != source) {
            throw Failure("export source must be normalized and absolute", EINVAL);
        }
        std::error_code error;
        auto canonical = std::filesystem::canonical(source, error);
        if (error) {
            throw Failure("cannot canonicalize export root", EACCES);
        }
        auto path = Path::parse(canonical.generic_string());
        if (!path) {
            throw Failure(path.error(), EACCES);
        }
        for (const auto &CEILING : ceilings_) {
            if (!CEILING.path.contains(*path)) {
                continue;
            }
            auto relative = path->string().substr(CEILING.path.string() == "/" ? 1 : CEILING.path.string().size());
            if (relative.starts_with('/')) {
                relative.erase(0, 1);
            }
            // Canonicalized components must not be replaced by a symlink while pinning.
            open_how how{};
            how.flags = O_PATH | O_DIRECTORY | O_CLOEXEC;
            how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
            int opened = static_cast<int>(::syscall(
                SYS_openat2, CEILING.directory.get(), relative.empty() ? "." : relative.c_str(), &how, sizeof(how)));
            if (opened < 0) {
                throw Failure("cannot securely pin export root", EACCES);
            }
            Fd directory(opened);
            std::lock_guard guard(mutex_);
            auto now = std::chrono::steady_clock::now();
            std::erase_if(roots_, [now](const auto &entry) -> bool { return entry.second.expires <= now; });
            if (roots_.size() >= MAX_SESSIONS * 4) {
                throw Failure("pinned root capacity reached; retry after expiry", EBUSY);
            }
            auto handle = peerfs::live::randomToken();
            roots_.emplace(handle, Root{source, *path, std::move(directory), now + SESSION_LIFETIME});
            return Json{{"ok", true}, {"root", path->string()}, {"handle", handle}};
        }
        throw Failure("export root is outside the owner's pinned ceilings", EACCES);
    }

    Network network_;
    std::vector<Ceiling> ceilings_;
    std::mutex mutex_;
    std::map<std::string, Root> roots_;
};

} // namespace
} // namespace peerfs::live

namespace peerfs {
std::expected<void, std::string> serveExporter(std::string_view network_file, std::string_view node_file) {
    try {
        auto network = peerfs::live::loadNetwork(network_file);
        peerfs::live::Exporter exporter(network, node_file);
        peerfs::live::serve(network,
                            [&exporter](std::string_view caller, const peerfs::live::Json &body) -> peerfs::live::Json {
                                return exporter.handle(caller, body);
                            });
        return {};
    } catch (const std::exception &ERROR) {
        return std::unexpected(ERROR.what());
    }
}
} // namespace peerfs
