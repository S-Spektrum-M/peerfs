#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <utility>

#include <peerfs/core.hpp>

extern char **environ;

namespace peerfs {
namespace {

constexpr std::size_t MAX_CONFIG_BYTES = 1024 * 1024;
constexpr std::size_t READ_BUFFER_BYTES = 4096;
constexpr auto PKL_TIMEOUT = std::chrono::seconds(30);
constexpr int POLL_INTERVAL_MS = 100;

class Pipe {
public:
    Pipe() = default;
    Pipe(const Pipe &) = delete;
    Pipe(Pipe &&) = delete;
    Pipe &operator=(const Pipe &) = delete;
    Pipe &operator=(Pipe &&) = delete;
    ~Pipe() {
        for (int descriptor : descriptors) {
            if (descriptor >= 0) {
                ::close(descriptor);
            }
        }
    }
    std::array<int, 2> descriptors = {-1, -1};
};

class SpawnActions {
public:
    SpawnActions() = default;
    SpawnActions(const SpawnActions &) = delete;
    SpawnActions(SpawnActions &&) = delete;
    SpawnActions &operator=(const SpawnActions &) = delete;
    SpawnActions &operator=(SpawnActions &&) = delete;
    ~SpawnActions() {
        if (initialized) {
            ::posix_spawn_file_actions_destroy(&actions);
        }
    }
    posix_spawn_file_actions_t actions{};
    bool initialized = false;
};

class Child {
public:
    explicit Child(pid_t process) : pid_(process) {
    }
    Child(const Child &) = delete;
    Child(Child &&) = delete;
    Child &operator=(const Child &) = delete;
    Child &operator=(Child &&) = delete;
    ~Child() {
        if (!reaped) {
            ::kill(pid_, SIGKILL);
            int status = 0;
            while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
            }
        }
    }
    [[nodiscard]] std::expected<int, std::string> finish(std::chrono::steady_clock::time_point deadline) {
        while (std::chrono::steady_clock::now() < deadline) {
            int status = 0;
            auto result = ::waitpid(pid_, &status, WNOHANG);
            if (result == pid_) {
                reaped = true;
                return status;
            }
            if (result < 0 && errno != EINTR) {
                return std::unexpected("waitpid failed");
            }
            ::poll(nullptr, 0, POLL_INTERVAL_MS);
        }
        return std::unexpected("pkl evaluation timed out");
    }

private:
    pid_t pid_;
    bool reaped = false;
};

std::expected<std::string, std::string> evaluatePkl(std::string_view filename) {
    Pipe pipe;
    if (::pipe2(pipe.descriptors.data(), O_CLOEXEC) < 0) {
        return std::unexpected("cannot create pkl output pipe");
    }
    SpawnActions actions;
    auto error = ::posix_spawn_file_actions_init(&actions.actions);
    if (error != 0) {
        return std::unexpected("cannot initialize pkl spawn actions");
    }
    actions.initialized = true;
    error = ::posix_spawn_file_actions_adddup2(&actions.actions, pipe.descriptors[1], STDOUT_FILENO);
    if (error != 0) {
        return std::unexpected("cannot redirect pkl output");
    }
    std::error_code path_error;
    auto absolute = std::filesystem::absolute(std::filesystem::path(filename), path_error).string();
    if (path_error) {
        return std::unexpected(path_error.message());
    }
    // posix_spawn's C API requires writable pointers; no shell interprets these arguments.
    std::array<std::string, 5> arguments = {"pkl", "eval", "--format", "yaml", absolute};
    std::array<char *, 6> argv{};
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        argv[index] = arguments[index].data();
    }
    pid_t pid = -1;
    error = ::posix_spawnp(&pid, "pkl", &actions.actions, nullptr, argv.data(), environ);
    if (error != 0) {
        return std::unexpected("cannot execute pkl: " + std::string(std::strerror(error)));
    }
    Child child(pid);
    ::close(pipe.descriptors[1]);
    pipe.descriptors[1] = -1;
    auto deadline = std::chrono::steady_clock::now() + PKL_TIMEOUT;
    std::string output;
    std::array<char, READ_BUFFER_BYTES> buffer{};
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd descriptor{pipe.descriptors[0], POLLIN, 0};
        auto ready = ::poll(&descriptor, 1, POLL_INTERVAL_MS);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected("cannot poll pkl output");
        }
        if (ready == 0) {
            continue;
        }
        auto count = ::read(pipe.descriptors[0], buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected("cannot read pkl output");
        }
        if (count == 0) {
            auto status = child.finish(deadline);
            if (!status) {
                return std::unexpected(status.error());
            }
            if (!WIFEXITED(*status) || WEXITSTATUS(*status) != 0) {
                return std::unexpected("pkl evaluation failed (see stderr)");
            }
            return output;
        }
        if (output.size() + static_cast<std::size_t>(count) > MAX_CONFIG_BYTES) {
            return std::unexpected("pkl output exceeds 1 MiB limit");
        }
        output.append(buffer.data(), static_cast<std::size_t>(count));
    }
    return std::unexpected("pkl evaluation timed out");
}

} // namespace

std::expected<std::string, std::string> loadConfig(std::string_view filename) {
    if (filename.empty() || filename.find('\0') != std::string_view::npos) {
        return std::unexpected("configuration filename must be nonempty and contain no NUL");
    }
    if (std::filesystem::path(filename).extension() == ".pkl") {
        return peerfs::evaluatePkl(filename);
    }
    std::ifstream input(std::string(filename), std::ios::binary);
    if (!input) {
        return std::unexpected("cannot open configuration: " + std::string(filename));
    }
    std::string output;
    std::array<char, READ_BUFFER_BYTES> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        auto count = static_cast<std::size_t>(input.gcount());
        if (output.size() + count > MAX_CONFIG_BYTES) {
            return std::unexpected("configuration exceeds 1 MiB limit");
        }
        output.append(buffer.data(), count);
    }
    if (!input.eof()) {
        return std::unexpected("cannot read configuration: " + std::string(filename));
    }
    return output;
}

} // namespace peerfs
