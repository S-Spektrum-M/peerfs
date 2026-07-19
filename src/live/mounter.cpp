#include <peerfs/live.hpp>

#define FUSE_USE_VERSION 35
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <limits>

#include <fuse3/fuse.h>

#include "runtime.hpp"

namespace peerfs::live {

Json admission(const Network &network, std::string_view topology_file, std::string_view home) {
    auto topology = peerfs::live::fileText(topology_file);
    auto parsed = peerfs::parseTopology(topology, home);
    if (!parsed) {
        throw Failure(parsed.error(), EINVAL);
    }
    return peerfs::live::request(
        network, network.authority, Json{{"op", "admit"}, {"topology", topology}, {"home", home}}, true);
}

namespace {

struct Mount {
    Network network;
    std::string owner;
    std::string name;
    std::string session;

    Json call(std::string_view operation, const char *path, const Json &arguments = Json::object()) const {
        if (!path || path[0] != '/') {
            throw Failure("invalid FUSE path", EINVAL);
        }
        auto body = arguments;
        body["op"] = operation;
        body["export"] = name;
        body["session"] = session;
        body["path"] = std::string_view(path).substr(1);
        return peerfs::live::request(network, owner, body);
    }
};

Mount &context() {
    return *static_cast<Mount *>(::fuse_get_context()->private_data);
}

bool safeTarget(std::string_view target) {
    std::error_code error;
    auto canonical = std::filesystem::canonical(target, error);
    if (error || canonical.string() != target) {
        return false;
    }
    auto current = std::filesystem::path(target);
    bool leaf = true;
    while (true) {
        struct stat metadata{};
        if (::lstat(current.c_str(), &metadata) < 0 || !S_ISDIR(metadata.st_mode)
            || (metadata.st_uid != 0 && metadata.st_uid != ::getuid())) {
            return false;
        }
        if (leaf && (metadata.st_uid != ::getuid() || (metadata.st_mode & 022))) {
            return false;
        }
        const bool ROOT_STICKY = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX);
        if ((metadata.st_mode & 022) && !ROOT_STICKY) {
            return false;
        }
        if (current == current.root_path()) {
            break;
        }
        current = current.parent_path();
        leaf = false;
    }
    return std::filesystem::is_empty(target);
}

int fuseGetattr(const char *path, struct stat *output, struct fuse_file_info *) noexcept {
    try {
        auto response = peerfs::live::context().call("stat", path);
        auto size = peerfs::live::number(response, "size");
        if (size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
            return -EOVERFLOW;
        }
        *output = {};
        auto directory = response.at("directory").get<bool>();
        output->st_mode = directory ? S_IFDIR | 0555 : S_IFREG | 0444;
        output->st_nlink = directory ? 2 : 1;
        output->st_uid = ::getuid();
        output->st_gid = ::getgid();
        output->st_size = static_cast<off_t>(size);
        output->st_ino = peerfs::live::number(response, "inode");
        output->st_mtim.tv_sec = response.at("mtime").get<time_t>();
        output->st_mtim.tv_nsec = response.at("mtime_ns").get<long>();
        return 0;
    } catch (const Failure &ERROR) {
        return -ERROR.code;
    } catch (...) {
        return -EIO;
    }
}

int fuseOpen(const char *path, struct fuse_file_info *info) noexcept {
    if ((info->flags & O_ACCMODE) != O_RDONLY || (info->flags & (O_CREAT | O_TRUNC | O_APPEND))) {
        return -EROFS;
    }
    try {
        static_cast<void>(peerfs::live::context().call("open", path));
        info->direct_io = 1;
        info->keep_cache = 0;
        return 0;
    } catch (const Failure &ERROR) {
        return -ERROR.code;
    } catch (...) {
        return -EIO;
    }
}

int fuseRead(const char *path, char *buffer, std::size_t size, off_t offset, struct fuse_file_info *) noexcept {
    if (offset < 0) {
        return -EINVAL;
    }
    try {
        auto bounded_size = std::min(size, MAX_READ);
        auto response = peerfs::live::context().call(
            "read", path, Json{{"offset", static_cast<std::uint64_t>(offset)}, {"size", bounded_size}});
        auto bytes = peerfs::live::decodeHex(peerfs::live::text(response, "data"));
        if (bytes.size() > bounded_size) {
            return -EIO;
        }
        std::memcpy(buffer, bytes.data(), bytes.size());
        return static_cast<int>(bytes.size());
    } catch (const Failure &ERROR) {
        return -ERROR.code;
    } catch (...) {
        return -EIO;
    }
}

int fuseReaddir(const char *path,
                void *buffer,
                fuse_fill_dir_t filler,
                off_t offset,
                struct fuse_file_info *,
                enum fuse_readdir_flags) noexcept {
    if (offset < 0) {
        return -EINVAL;
    }
    try {
        auto index = static_cast<std::uint64_t>(offset);
        while (true) {
            auto response = peerfs::live::context().call("readdir", path, Json{{"offset", index}});
            auto names = response.at("names");
            auto types = response.value("types", Json::array());
            if (!names.is_array() || !types.is_array() || (!types.empty() && types.size() != names.size())) {
                return -EIO;
            }
            for (std::size_t position = 0; position < names.size(); ++position) {
                auto name = names[position].get<std::string>();
                struct stat kind{};
                if (!types.empty()) {
                    auto type = types[position].get<std::string>();
                    kind.st_mode = type == "d" ? S_IFDIR : type == "f" ? S_IFREG : 0;
                }
                if (name.empty() || name.find('/') != std::string::npos || name.find('\0') != std::string::npos) {
                    return -EIO;
                }
                ++index;
                if (filler(
                        buffer, name.c_str(), &kind, static_cast<off_t>(index), static_cast<fuse_fill_dir_flags>(0))) {
                    return 0;
                }
            }
            if (response.at("end").get<bool>()) {
                return 0;
            }
            if (peerfs::live::number(response, "next") != index || names.empty()) {
                return -EIO;
            }
        }
    } catch (const Failure &ERROR) {
        return -ERROR.code;
    } catch (...) {
        return -EIO;
    }
}

void *fuseInit(struct fuse_conn_info *connection, struct fuse_config *config) noexcept {
    connection->want &= ~FUSE_CAP_WRITEBACK_CACHE;
    config->kernel_cache = 0;
    config->auto_cache = 0;
    config->direct_io = 1;
    config->entry_timeout = 0;
    config->attr_timeout = 0;
    config->negative_timeout = 0;
    return ::fuse_get_context()->private_data;
}

} // namespace
} // namespace peerfs::live

namespace peerfs {

std::expected<std::string, std::string> authorityStatus(std::string_view network_file) {
    try {
        auto network = peerfs::live::loadNetwork(network_file);
        return peerfs::live::request(network, network.authority, peerfs::live::Json{{"op", "status"}}, true).dump(2)
               + '\n';
    } catch (const std::exception &ERROR) {
        return std::unexpected(ERROR.what());
    }
}

std::expected<std::string, std::string>
admitDevice(std::string_view network_file, std::string_view topology_file, std::string_view home) {
    try {
        auto network = peerfs::live::loadNetwork(network_file);
        return peerfs::live::admission(network, topology_file, home).dump(2) + '\n';
    } catch (const std::exception &ERROR) {
        return std::unexpected(ERROR.what());
    }
}

std::expected<void, std::string> mountExport(std::string_view network_file,
                                             std::string_view topology_file,
                                             std::string_view home,
                                             std::string_view export_name) {
    try {
        if (::geteuid() == 0 || ::getuid() == 0 || ::getuid() != ::geteuid() || ::getgid() != ::getegid()) {
            throw peerfs::live::Failure("mount as a non-root user", EACCES);
        }
        auto network = peerfs::live::loadNetwork(network_file);
        auto admitted = peerfs::live::admission(network, topology_file, home);
        if (!admitted.at("admitted").get<bool>()) {
            return std::unexpected("admission refused:\n" + admitted.dump(2));
        }
        for (const auto &ENTRY : admitted.at("entries")) {
            if (peerfs::live::text(ENTRY, "export") != export_name) {
                continue;
            }
            auto target = peerfs::live::text(ENTRY, "target");
            if (!peerfs::live::safeTarget(target)) {
                return std::unexpected("mount target must be empty, owned by you, non-aliased and under safe "
                                       "non-writable-by-others parents: "
                                       + target);
            }
            peerfs::live::Mount mount{network,
                                      peerfs::live::text(ENTRY, "owner"),
                                      std::string(export_name),
                                      peerfs::live::text(admitted, "session")};
            struct fuse_operations operations{};
            operations.getattr = peerfs::live::fuseGetattr;
            operations.open = peerfs::live::fuseOpen;
            operations.read = peerfs::live::fuseRead;
            operations.readdir = peerfs::live::fuseReaddir;
            operations.init = peerfs::live::fuseInit;
            // No default_permissions: without allow_other only this user can reach the
            // mount, the modes we report always grant them read, and the exporter
            // authorizes every request. Kernel mode checks only cost a getattr RPC
            // per path component.
            std::array<std::string, 6> arguments = {"peerfs", "-f", "-s", "-o", "ro", target};
            std::array<char *, 6> argv{};
            for (std::size_t index = 0; index < arguments.size(); ++index) {
                argv[index] = arguments[index].data();
            }
            if (::fuse_main_real(static_cast<int>(argv.size()), argv.data(), &operations, sizeof(operations), &mount)
                != 0) {
                return std::unexpected("FUSE mount failed; see stderr");
            }
            return {};
        }
        return std::unexpected("selected export is not in the admitted plan");
    } catch (const std::exception &ERROR) {
        return std::unexpected(ERROR.what());
    }
}

} // namespace peerfs
