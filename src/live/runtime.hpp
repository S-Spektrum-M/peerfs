#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <nlohmann/json.hpp>

#include <peerfs/core.hpp>

namespace peerfs::live {

using Json = nlohmann::json;
constexpr std::size_t MAX_FRAME = 1024 * 1024;
constexpr std::size_t MAX_READ = 256 * 1024;
static_assert(MAX_READ * 2 + 4096 <= MAX_FRAME, "hex-encoded reads must fit one frame");
constexpr std::size_t MAX_SESSIONS = 1024;
constexpr auto SESSION_LIFETIME = std::chrono::hours(1);
constexpr int RPC_TIMEOUT_MS = 5000;

class Failure : public std::runtime_error {
public:
    explicit Failure(std::string_view message, int code = 5) : std::runtime_error(std::string(message)), code(code) {
    }
    int code;
};

class Fd {
public:
    Fd() = default;
    explicit Fd(int value);
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    Fd(Fd &&other) noexcept;
    Fd &operator=(Fd &&other) noexcept;
    ~Fd();
    [[nodiscard]] int get() const;
    [[nodiscard]] int release();

private:
    int value_ = -1;
};

struct Peer {
    std::string id;
    std::string address;
    std::uint16_t port = 0;
};

struct Network {
    std::string self;
    std::string authority;
    std::string socket = "/var/run/tailscale/tailscaled.sock";
    std::map<std::string, Peer> peers;
    bool test_loopback = false;
    std::uint16_t authority_port = 7443;
};

[[nodiscard]] Json parseJson(std::string_view text);
void fields(const Json &object, std::initializer_list<std::string_view> names);
[[nodiscard]] std::string text(const Json &object, std::string_view name);
[[nodiscard]] std::uint64_t number(const Json &object, std::string_view name);
[[nodiscard]] Network loadNetwork(std::string_view filename);
[[nodiscard]] std::string fileText(std::string_view filename);
[[nodiscard]] std::string identity(const Network &network, std::string_view address);
[[nodiscard]] Json request(const Network &network, std::string_view peer, const Json &body, bool control = false);
using Handler = std::function<Json(std::string_view, const Json &)>;
void serve(const Network &network, const Handler &handler, bool control = false);
[[nodiscard]] std::string randomToken();
[[nodiscard]] Json admission(const Network &network, std::string_view topology_file, std::string_view home);
[[nodiscard]] std::string encodeHex(std::string_view data);
[[nodiscard]] std::string decodeHex(std::string_view data);
[[nodiscard]] Fd openBeneath(int root, std::string_view relative, std::uint64_t flags);
[[nodiscard]] std::string relativePath(std::string_view path);
[[nodiscard]] Json success();
[[nodiscard]] Json refusal(int code, std::string_view message);

} // namespace peerfs::live
