#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <filesystem>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <vector>

#include "runtime.hpp"
#include <peerfs/live.hpp>

namespace peerfs::live {
namespace {

constexpr std::size_t MAX_LIVE_RULE_BYTES = 128 * 1024;
constexpr std::size_t MAX_EXPORTS = 64;

struct Session {
    std::string device;
    std::uint64_t version;
    Json exports;
    std::chrono::steady_clock::time_point expires;
};

class Authority {
public:
    Authority(const Network &network, std::string_view rules, std::string_view state)
        : network_(network), rules_file_(rules) {
        if (network.self != network.authority) {
            throw Failure("authority must run as the enrolled authority peer", EACCES);
        }
        auto directory = std::filesystem::path(state);
        if (!directory.is_absolute()) {
            throw Failure("state directory must be absolute", EINVAL);
        }
        if (std::filesystem::create_directory(directory)) {
            ::chmod(directory.c_str(), 0700);
        }
        directory_ = Fd(::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        struct stat metadata{};
        if (::fstat(directory_.get(), &metadata) < 0 || metadata.st_uid != ::getuid()
            || (metadata.st_mode & 077) != 0) {
            throw Failure("authority state directory must be owned by this user and mode 0700", EACCES);
        }
        lock_ = Fd(::openat(directory_.get(), "lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600));
        if (::flock(lock_.get(), LOCK_EX | LOCK_NB) < 0) {
            throw Failure("authority state is already in use", EBUSY);
        }
        Fd snapshot;
        int existing = ::openat(directory_.get(), "snapshot.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (existing >= 0) {
            snapshot = Fd(existing);
            std::string wire;
            std::array<char, 4096> buffer{};
            while (true) {
                auto count = ::read(snapshot.get(), buffer.data(), buffer.size());
                if (count < 0 && errno == EINTR) {
                    continue;
                }
                if (count < 0) {
                    throw Failure("cannot read saved rules snapshot");
                }
                if (count == 0) {
                    break;
                }
                wire.append(buffer.data(), static_cast<std::size_t>(count));
                if (wire.size() > MAX_FRAME) {
                    throw Failure("saved snapshot too large");
                }
            }
            auto saved = peerfs::live::parseJson(wire);
            version_ = peerfs::live::number(saved, "version");
            previous_text_ = peerfs::live::text(saved, "rules");
        } else if (errno != ENOENT) {
            throw Failure("cannot open saved rules snapshot");
        }
        this->refresh();
    }

    Json handle(std::string_view caller, const Json &body) {
        auto operation = peerfs::live::text(body, "op");
        if (operation == "admit") {
            return this->admit(caller, body);
        }
        std::lock_guard guard(mutex_);
        this->refresh();
        if (operation == "status") {
            peerfs::live::fields(body, {"op"});
            return Json{{"ok", true}, {"version", version_}, {"read_only", true}};
        }
        if (operation != "authorize") {
            throw Failure("unsupported authority operation", ENOSYS);
        }
        peerfs::live::fields(body, {"op", "session", "export", "device"});
        auto token = peerfs::live::text(body, "session");
        auto name = peerfs::live::text(body, "export");
        auto device = peerfs::live::text(body, "device");
        auto session = sessions_.find(token);
        if (session == sessions_.end() || session->second.device != device || session->second.version != version_
            || session->second.expires <= std::chrono::steady_clock::now() || !session->second.exports.contains(name)) {
            throw Failure("session absent, expired or invalidated; re-admission required", EACCES);
        }
        auto approved = session->second.exports.at(name);
        if (peerfs::live::text(approved, "owner") != caller) {
            throw Failure("only the export owner may authorize reads", EACCES);
        }
        bool granted = false;
        for (const auto &RULE : rules_) {
            granted = granted || (RULE.name == name && RULE.owner == caller && RULE.grants.contains(device));
        }
        if (!granted) {
            throw Failure("grant revoked", EACCES);
        }
        approved["ok"] = true;
        approved["version"] = version_;
        return approved;
    }

private:
    void persist(std::string_view rules, std::uint64_t version) {
        auto temporary = ".snapshot-" + peerfs::live::randomToken();
        Fd output(::openat(directory_.get(), temporary.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600));
        auto wire = Json{{"version", version}, {"rules", rules}}.dump();
        std::size_t offset = 0;
        try {
            while (offset < wire.size()) {
                auto count = ::write(output.get(), wire.data() + offset, wire.size() - offset);
                if (count < 0 && errno == EINTR) {
                    continue;
                }
                if (count <= 0) {
                    throw Failure("cannot persist rules snapshot");
                }
                offset += static_cast<std::size_t>(count);
            }
            if (::fsync(output.get()) < 0
                || ::renameat(directory_.get(), temporary.c_str(), directory_.get(), "snapshot.json") < 0
                || ::fsync(directory_.get()) < 0) {
                throw Failure("cannot atomically persist rules version");
            }
        } catch (...) {
            ::unlinkat(directory_.get(), temporary.c_str(), 0);
            throw;
        }
    }

    // Caller holds mutex once serving starts. Invalid edits fail closed; never
    // fall back to old permissions when the rules file cannot be read or parsed.
    void refresh() {
        auto wire = peerfs::live::fileText(rules_file_);
        if (wire.size() > MAX_LIVE_RULE_BYTES) {
            throw Failure("live rules limit is 128 KiB", E2BIG);
        }
        // The file is reread on every request; only an unchanged text reuses its
        // (pure) parse. Any edit, including an invalid one, is parsed afresh.
        std::optional<std::vector<Export>> parsed;
        if (wire != parsed_text_) {
            auto result = peerfs::parseRules(wire);
            if (!result || result->size() > MAX_EXPORTS) {
                throw Failure("invalid rules or more than 64 exports", EINVAL);
            }
            parsed = std::move(*result);
        }
        if (wire != previous_text_ || version_ == 0) {
            if (version_ == std::numeric_limits<std::uint64_t>::max()) {
                throw Failure("rule version exhausted");
            }
            this->persist(wire, version_ + 1);
            ++version_;
            previous_text_ = wire;
            sessions_.clear();
        }
        if (parsed) {
            rules_ = std::move(*parsed);
            parsed_text_ = wire;
        }
        auto now = std::chrono::steady_clock::now();
        std::erase_if(sessions_, [now](const auto &entry) -> bool { return entry.second.expires <= now; });
    }

    Json admit(std::string_view caller, const Json &body) {
        peerfs::live::fields(body, {"op", "topology", "home"});
        auto topology = peerfs::parseTopology(peerfs::live::text(body, "topology"), peerfs::live::text(body, "home"));
        if (!topology) {
            throw Failure(topology.error(), EINVAL);
        }
        std::vector<Export> snapshot;
        std::uint64_t version = 0;
        {
            std::lock_guard guard(mutex_);
            this->refresh();
            snapshot = rules_;
            version = version_;
        }
        std::set<std::string> needed_owners;
        for (const auto &RULE : snapshot) {
            if (RULE.grants.contains(std::string(caller))) {
                needed_owners.insert(RULE.owner);
            }
        }
        std::vector<Json> proofs;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        auto check =
            [this, &proofs, &needed_owners, deadline](const Export &export_rule) -> std::expected<Path, std::string> {
            proofs.push_back(Json::object());
            // PF5 needs all roots on relevant owners, but an unrelated offline
            // owner must not consume this device's verification budget.
            if (!needed_owners.contains(export_rule.owner)) {
                return std::unexpected("owner not involved in this plan");
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                return std::unexpected("owner verification budget exceeded");
            }
            try {
                auto response = peerfs::live::request(
                    network_,
                    export_rule.owner,
                    Json{{"op", "verify"}, {"export", export_rule.name}, {"path", export_rule.path.string()}});
                auto canonical = Path::parse(peerfs::live::text(response, "root"));
                if (!canonical) {
                    return canonical;
                }
                if (peerfs::live::text(response, "handle").empty()) {
                    return std::unexpected("missing pinned root handle");
                }
                proofs.back() = response;
                return canonical;
            } catch (const std::exception &ERROR) {
                return std::unexpected(ERROR.what());
            }
        };
        auto plan = peerfs::compilePlan(snapshot, caller, *topology, check);
        Json result{{"ok", true},
                    {"admitted", false},
                    {"version", version},
                    {"read_only", true},
                    {"device", caller},
                    {"entries", Json::array()},
                    {"issues", Json::array()}};
        for (const auto &ISSUE : plan.issues) {
            result["issues"].push_back(
                Json{{"check", ISSUE.check}, {"export", ISSUE.export_name}, {"message", ISSUE.message}});
        }
        Json approved = Json::object();
        for (const auto &ENTRY : plan.entries) {
            result["entries"].push_back(Json{{"export", ENTRY.name},
                                             {"owner", ENTRY.owner},
                                             {"source", ENTRY.source.string()},
                                             {"target", ENTRY.target.string()},
                                             {"mode", "r"}});
            for (std::size_t index = 0; index < snapshot.size(); ++index) {
                if (snapshot[index].name == ENTRY.name && snapshot[index].owner == ENTRY.owner
                    && !proofs[index].empty()) {
                    approved[ENTRY.name] = Json{{"owner", ENTRY.owner},
                                                {"source", ENTRY.source.string()},
                                                {"root", proofs[index].at("root")},
                                                {"handle", proofs[index].at("handle")}};
                }
            }
        }
        if (!plan.valid()) {
            return result;
        }
        std::lock_guard guard(mutex_);
        this->refresh();
        if (version != version_) {
            throw Failure("rules changed during admission; retry", EAGAIN);
        }
        if (sessions_.size() >= MAX_SESSIONS) {
            throw Failure("session capacity reached", EBUSY);
        }
        auto token = peerfs::live::randomToken();
        sessions_.emplace(
            token,
            Session{std::string(caller), version_, approved, std::chrono::steady_clock::now() + SESSION_LIFETIME});
        result["admitted"] = true;
        result["session"] = token;
        result["expires_in_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(SESSION_LIFETIME).count();
        return result;
    }

    Network network_;
    std::string rules_file_;
    Fd directory_;
    Fd lock_;
    std::mutex mutex_;
    std::string previous_text_;
    std::optional<std::string> parsed_text_;
    std::uint64_t version_ = 0;
    std::vector<Export> rules_;
    std::map<std::string, Session> sessions_;
};

} // namespace
} // namespace peerfs::live

namespace peerfs {
std::expected<void, std::string>
serveAuthority(std::string_view network_file, std::string_view rules_file, std::string_view state_directory) {
    try {
        if (::geteuid() == 0 || ::getuid() == 0) {
            throw peerfs::live::Failure("authority must run as a non-root user", EACCES);
        }
        auto network = peerfs::live::loadNetwork(network_file);
        peerfs::live::Authority authority(network, rules_file, state_directory);
        peerfs::live::serve(
            network,
            [&authority](std::string_view caller, const peerfs::live::Json &body) -> peerfs::live::Json {
                return authority.handle(caller, body);
            },
            true);
        return {};
    } catch (const std::exception &ERROR) {
        return std::unexpected(ERROR.what());
    }
}
} // namespace peerfs
