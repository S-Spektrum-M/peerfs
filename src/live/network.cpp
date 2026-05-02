#include <fcntl.h>
#include <poll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "runtime.hpp"

namespace peerfs::live {
namespace {

std::atomic<bool> STOP = false;
static_assert(std::atomic<bool>::is_always_lock_free, "signal stop flag must be lock-free");
constexpr std::size_t MAX_JSON_DEPTH = 32;
constexpr std::uint32_t TAILNET_MASK = 0xffc00000;
constexpr std::uint32_t TAILNET_PREFIX = 0x64400000;
constexpr std::uint32_t LOOPBACK_MASK = 0xff000000;
constexpr std::uint32_t LOOPBACK_PREFIX = 0x7f000000;

void stopSignal(int) {
    STOP.store(true);
}

class CurlGlobal {
public:
    CurlGlobal() {
        if (::curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            throw Failure("curl initialization failed");
        }
    }
    CurlGlobal(const CurlGlobal &) = delete;
    CurlGlobal(CurlGlobal &&) = delete;
    CurlGlobal &operator=(const CurlGlobal &) = delete;
    CurlGlobal &operator=(CurlGlobal &&) = delete;
    ~CurlGlobal() {
        ::curl_global_cleanup();
    }
};

void initializeCurl() {
    static CurlGlobal runtime;
    static_cast<void>(runtime);
}

sockaddr_in address(std::string_view ip, std::uint16_t port) {
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_port = ::htons(port);
    if (::inet_pton(AF_INET, std::string(ip).c_str(), &result.sin_addr) != 1) {
        throw Failure("expected a numeric IPv4 Tailscale address", EINVAL);
    }
    return result;
}

void waitReady(int fd, short events, std::chrono::steady_clock::time_point deadline) {
    while (true) {
        auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) {
            throw Failure("RPC timed out", ETIMEDOUT);
        }
        pollfd descriptor{fd, events, 0};
        auto status = ::poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (status > 0) {
            if (descriptor.revents & POLLNVAL) {
                throw Failure("invalid RPC socket", EBADF);
            }
            return;
        }
        if (status == 0 || errno != EINTR) {
            throw Failure("RPC timeout or poll failure", ETIMEDOUT);
        }
    }
}

void transfer(int fd, char *data, std::size_t size, bool send, std::chrono::steady_clock::time_point deadline) {
    std::size_t offset = 0;
    while (offset < size) {
        peerfs::live::waitReady(fd, send ? POLLOUT : POLLIN, deadline);
        auto count =
            send ? ::send(fd, data + offset, size - offset, MSG_NOSIGNAL) : ::recv(fd, data + offset, size - offset, 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (count <= 0) {
            throw Failure("RPC connection closed", ECONNRESET);
        }
        offset += static_cast<std::size_t>(count);
    }
}

void sendFrame(int fd, const Json &body) {
    auto wire = body.dump();
    if (wire.size() > MAX_FRAME) {
        throw Failure("RPC frame too large", E2BIG);
    }
    auto length = ::htonl(static_cast<std::uint32_t>(wire.size()));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(RPC_TIMEOUT_MS);
    // One send per frame: split header writes stall on Nagle/delayed ACK once
    // connections are reused.
    std::string frame = "PFS1";
    frame.append(reinterpret_cast<const char *>(&length), sizeof(length));
    frame += wire;
    peerfs::live::transfer(fd, frame.data(), frame.size(), true, deadline);
}

void noDelay(int fd) {
    int enabled = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
}

Json receiveFrame(int fd, int timeout_ms = RPC_TIMEOUT_MS) {
    std::uint32_t length = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::array<char, 4> magic{};
    peerfs::live::transfer(fd, magic.data(), magic.size(), false, deadline);
    if (std::string_view(magic.data(), magic.size()) != "PFS1") {
        throw Failure("unsupported RPC protocol", EPROTO);
    }
    peerfs::live::transfer(fd, reinterpret_cast<char *>(&length), sizeof(length), false, deadline);
    auto size = ::ntohl(length);
    if (size == 0 || size > MAX_FRAME) {
        throw Failure("invalid RPC frame size", E2BIG);
    }
    std::string wire(size, '\0');
    peerfs::live::transfer(fd, wire.data(), wire.size(), false, deadline);
    return peerfs::live::parseJson(wire);
}

std::size_t appendCurl(char *data, std::size_t size, std::size_t count, void *context) noexcept {
    auto &output = *static_cast<std::string *>(context);
    if (size != 0 && count > MAX_FRAME / size) {
        return 0;
    }
    auto bytes = size * count;
    if (output.size() + bytes > MAX_FRAME) {
        return 0;
    }
    try {
        output.append(data, bytes);
        return bytes;
    } catch (...) {
        return 0;
    }
}

} // namespace

Fd::Fd(int value) : value_(value) {
    if (value < 0) {
        throw Failure(std::strerror(errno), errno);
    }
}
Fd::Fd(Fd &&other) noexcept : value_(std::exchange(other.value_, -1)) {
}
Fd &Fd::operator=(Fd &&other) noexcept {
    if (this != &other) {
        if (value_ >= 0) {
            ::close(value_);
        }
        value_ = std::exchange(other.value_, -1);
    }
    return *this;
}
Fd::~Fd() {
    if (value_ >= 0) {
        ::close(value_);
    }
}
int Fd::get() const {
    return value_;
}
int Fd::release() {
    return std::exchange(value_, -1);
}

Json parseJson(std::string_view wire) {
    if (wire.empty() || wire.size() > MAX_FRAME) {
        throw Failure("JSON input must be nonempty and at most 1 MiB", E2BIG);
    }
    std::vector<std::set<std::string>> keys;
    auto validate = [&keys](int depth, Json::parse_event_t event, Json &value) -> bool {
        if (depth < 0 || static_cast<std::size_t>(depth) > MAX_JSON_DEPTH) {
            throw Failure("JSON nesting limit exceeded", E2BIG);
        }
        if (event == Json::parse_event_t::object_start) {
            keys.emplace_back();
        } else if (event == Json::parse_event_t::object_end) {
            keys.pop_back();
        } else if (event == Json::parse_event_t::key && !keys.back().insert(value.get<std::string>()).second) {
            throw Failure("duplicate JSON key", EINVAL);
        }
        return true;
    };
    auto result = Json::parse(wire, validate);
    if (!result.is_object()) {
        throw Failure("expected a JSON object", EINVAL);
    }
    return result;
}

void fields(const Json &object, std::initializer_list<std::string_view> names) {
    if (!object.is_object()) {
        throw Failure("expected an object", EINVAL);
    }
    for (auto item = object.begin(); item != object.end(); ++item) {
        bool allowed = false;
        for (auto name : names) {
            allowed = allowed || item.key() == name;
        }
        if (!allowed) {
            throw Failure("unknown field: " + item.key(), EINVAL);
        }
    }
}
std::string text(const Json &object, std::string_view name) {
    auto value = object.at(std::string(name)).get<std::string>();
    if (value.find('\0') != std::string::npos) {
        throw Failure("NUL in string field", EINVAL);
    }
    return value;
}
std::uint64_t number(const Json &object, std::string_view name) {
    auto &value = object.at(std::string(name));
    if (!value.is_number_unsigned()) {
        throw Failure("expected unsigned integer", EINVAL);
    }
    return value.get<std::uint64_t>();
}
std::string fileText(std::string_view filename) {
    if (filename.ends_with(".pkl")) {
        throw Failure("live service inputs must be plain files, not executable Pkl modules", EINVAL);
    }
    auto result = peerfs::loadConfig(filename);
    if (!result) {
        throw Failure(result.error(), EINVAL);
    }
    return *result;
}

Network loadNetwork(std::string_view filename) {
    auto config = peerfs::live::parseJson(peerfs::live::fileText(filename));
    peerfs::live::fields(config, {"self", "authority", "authority_port", "tailscale_socket", "peers", "test_loopback"});
    Network result;
    result.self = peerfs::live::text(config, "self");
    result.authority = peerfs::live::text(config, "authority");
    if (config.contains("tailscale_socket")) {
        result.socket = peerfs::live::text(config, "tailscale_socket");
        if (result.socket.empty() || result.socket.front() != '/') {
            throw Failure("tailscale_socket must be absolute", EINVAL);
        }
    }
    result.test_loopback = config.value("test_loopback", false);
#if !FF_peerfs__test_transport
    if (result.test_loopback) {
        throw Failure("loopback transport is disabled in production builds", EACCES);
    }
#endif
    if (config.contains("authority_port")) {
        auto port = peerfs::live::number(config, "authority_port");
        if (port == 0 || port > std::numeric_limits<std::uint16_t>::max()) {
            throw Failure("invalid authority port", EINVAL);
        }
        result.authority_port = static_cast<std::uint16_t>(port);
    }
    auto &peers = config.at("peers");
    if (!peers.is_object() || peers.empty()) {
        throw Failure("peers must be a nonempty object", EINVAL);
    }
    std::set<std::string> ids;
    std::set<std::string> addresses;
    for (auto item = peers.begin(); item != peers.end(); ++item) {
        peerfs::live::fields(item.value(), {"id", "address", "port"});
        Peer peer;
        peer.id = peerfs::live::text(item.value(), "id");
        peer.address = peerfs::live::text(item.value(), "address");
        auto port = item.value().contains("port") ? peerfs::live::number(item.value(), "port") : 7444;
        if (port == 0 || port > std::numeric_limits<std::uint16_t>::max() || peer.id.empty()) {
            throw Failure("invalid peer port or StableID", EINVAL);
        }
        peer.port = static_cast<std::uint16_t>(port);
        auto socket_address = peerfs::live::address(peer.address, peer.port);
        auto ip = ::ntohl(socket_address.sin_addr.s_addr);
        const bool VALID_IP =
            result.test_loopback ? (ip & LOOPBACK_MASK) == LOOPBACK_PREFIX : (ip & TAILNET_MASK) == TAILNET_PREFIX;
        if (!VALID_IP || !ids.insert(peer.id).second || !addresses.insert(peer.address).second) {
            throw Failure("peer addresses/StableIDs must be unique and on the selected network", EINVAL);
        }
        result.peers.emplace(item.key(), std::move(peer));
    }
    if (!result.peers.contains(result.self) || !result.peers.contains(result.authority)) {
        throw Failure("self and authority must be enrolled peers", EINVAL);
    }
    peerfs::live::initializeCurl();
    return result;
}

std::string identity(const Network &network, std::string_view address) {
    std::unique_ptr<CURL, decltype(&::curl_easy_cleanup)> curl(::curl_easy_init(), ::curl_easy_cleanup);
    if (!curl) {
        throw Failure("cannot initialize WhoIs client", EACCES);
    }
    // Address is numeric IPv4:port from the connected socket, not from an RPC field.
    auto url = "http://local-tailscaled.sock/localapi/v0/whois?addr=" + std::string(address);
    std::string output;
    ::curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    ::curl_easy_setopt(curl.get(), CURLOPT_UNIX_SOCKET_PATH, network.socket.c_str());
    ::curl_easy_setopt(curl.get(), CURLOPT_PROXY, "");
    ::curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    ::curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(RPC_TIMEOUT_MS));
    ::curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, peerfs::live::appendCurl);
    ::curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &output);
    auto status = ::curl_easy_perform(curl.get());
    long http_status = 0;
    ::curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_status);
    if (status != CURLE_OK || http_status != 200) {
        throw Failure("tailscaled WhoIs unavailable or refused the peer", EACCES);
    }
    auto response = peerfs::live::parseJson(output);
    auto id = peerfs::live::text(response.at("Node"), "StableID");
    for (const auto &[NAME, PEER] : network.peers) {
        if (PEER.id == id) {
            // Also pin each enrollment to its configured address. Routed/subnet peers
            // and forwarded HTTP identity headers are intentionally unsupported.
            if (address.substr(0, address.find(':')) != PEER.address) {
                throw Failure("WhoIs address does not match enrollment", EACCES);
            }
            return NAME;
        }
    }
    throw Failure("peer StableID is not enrolled", EACCES);
}

namespace {

Fd connectPeer(const Network &network, std::string_view peer_name, bool control) {
    auto &peer = network.peers.at(std::string(peer_name));
    Fd connection(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    peerfs::live::noDelay(connection.get());
    auto source = peerfs::live::address(network.peers.at(network.self).address, 0);
    if (::bind(connection.get(), reinterpret_cast<sockaddr *>(&source), sizeof(source)) < 0) {
        throw Failure("cannot bind RPC source to this device's enrolled address", errno);
    }
    auto target = peerfs::live::address(peer.address, control ? network.authority_port : peer.port);
    if (::connect(connection.get(), reinterpret_cast<sockaddr *>(&target), sizeof(target)) < 0) {
        if (errno != EINPROGRESS) {
            throw Failure("cannot connect to peer", EHOSTUNREACH);
        }
        peerfs::live::waitReady(
            connection.get(), POLLOUT, std::chrono::steady_clock::now() + std::chrono::milliseconds(RPC_TIMEOUT_MS));
        int error = 0;
        socklen_t length = sizeof(error);
        if (::getsockopt(connection.get(), SOL_SOCKET, SO_ERROR, &error, &length) < 0 || error != 0) {
            throw Failure("peer connection failed", EHOSTUNREACH);
        }
    }
    auto endpoint = peer.address + ':' + std::to_string(control ? network.authority_port : peer.port);
    if (peerfs::live::identity(network, endpoint) != peer_name) {
        throw Failure("unexpected server identity", EACCES);
    }
    return connection;
}

// A reused connection must have nothing pending: a readable idle socket means
// the server closed it (or desynchronized), so it is discarded, never read.
bool idleAndOpen(int fd) {
    pollfd descriptor{fd, POLLIN, 0};
    return ::poll(&descriptor, 1, 0) == 0;
}

} // namespace

Json request(const Network &network, std::string_view peer_name, const Json &body, bool control) {
    constexpr int ADMISSION_TIMEOUT_MS = 30000;
    // Server identity is WhoIs-bound to each TCP connection, so idempotent reads
    // may reuse one; every request is still authorized afresh by its handler.
    // Admission is not idempotent and keeps a dedicated connection.
    const bool ADMIT = body.value("op", "") == "admit";
    thread_local std::map<std::string, Fd> pool;
    auto key = std::string(peer_name) + (control ? "/control" : "/data");
    auto exchange = [&body, ADMIT](int fd) -> Json {
        peerfs::live::sendFrame(fd, body);
        return peerfs::live::receiveFrame(fd, ADMIT ? ADMISSION_TIMEOUT_MS : RPC_TIMEOUT_MS);
    };
    Json response;
    auto cached = ADMIT ? pool.end() : pool.find(key);
    if (cached != pool.end()) {
        auto connection = std::move(cached->second);
        pool.erase(cached);
        try {
            if (!peerfs::live::idleAndOpen(connection.get())) {
                throw Failure("pooled RPC connection closed", ECONNRESET);
            }
            response = exchange(connection.get());
            pool.insert_or_assign(key, std::move(connection));
        } catch (const Failure &ERROR) {
            if (ERROR.code != ECONNRESET) {
                throw;
            }
        }
    }
    if (response.is_null()) {
        auto connection = peerfs::live::connectPeer(network, peer_name, control);
        response = exchange(connection.get());
        if (!ADMIT) {
            pool.insert_or_assign(key, std::move(connection));
        }
    }
    if (!response.at("ok").get<bool>()) {
        auto error = peerfs::live::number(response, "errno");
        constexpr std::uint64_t MAX_ERRNO = 4095;
        if (error == 0 || error > MAX_ERRNO) {
            throw Failure("invalid remote error code", EIO);
        }
        throw Failure(peerfs::live::text(response, "error"), static_cast<int>(error));
    }
    return response;
}

Json success() {
    return Json{{"ok", true}};
}
Json refusal(int code, std::string_view message) {
    return Json{{"ok", false}, {"errno", code}, {"error", message}};
}

void serve(const Network &network, const Handler &handler, bool control) {
    if (::geteuid() == 0 || ::getuid() == 0 || ::getuid() != ::geteuid() || ::getgid() != ::getegid()) {
        throw Failure("run PeerFS services directly as a dedicated non-root user, without setuid/setgid", EACCES);
    }
    auto &self = network.peers.at(network.self);
    if (peerfs::live::identity(network, self.address + ":0") != network.self) {
        throw Failure("local device identity does not match enrollment", EACCES);
    }
    Fd listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    int reuse = 1;
    ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    auto local = peerfs::live::address(self.address, control ? network.authority_port : self.port);
    if (::bind(listener.get(), reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0
        || ::listen(listener.get(), 64) < 0) {
        throw Failure("cannot listen on enrolled address/port", errno);
    }
    STOP.store(false);
    std::signal(SIGINT, peerfs::live::stopSignal);
    std::signal(SIGTERM, peerfs::live::stopSignal);
    std::cerr << "PeerFS " << (control ? "authority" : "exporter") << " listening on " << self.address << ':'
              << (control ? network.authority_port : self.port) << '\n';
    struct Job {
        Fd connection;
        std::string endpoint;
    };
    std::mutex queue_mutex;
    std::condition_variable_any ready;
    std::deque<Job> queue;
    constexpr std::size_t WORKERS = 8;
    constexpr std::size_t QUEUE_LIMIT = 32;
    std::vector<std::jthread> workers;
    for (std::size_t index = 0; index < WORKERS; ++index) {
        workers.emplace_back([&network, &handler, &queue_mutex, &ready, &queue](std::stop_token stop) -> void {
            while (!stop.stop_requested()) {
                Job job;
                {
                    std::unique_lock guard(queue_mutex);
                    if (!ready.wait(guard, stop, [&queue]() -> bool { return !queue.empty(); })) {
                        return;
                    }
                    job = std::move(queue.front());
                    queue.pop_front();
                }
                // Keep the connection for further requests while it stays busy, up to
                // a bounded lifetime, and yield it as soon as other clients queue.
                auto waitNext = [&stop, &queue_mutex, &queue](int fd,
                                                              std::chrono::steady_clock::time_point retire) -> bool {
                    constexpr auto IDLE = std::chrono::milliseconds(1000);
                    constexpr int SLICE_MS = 20;
                    auto idle_until = std::min(retire, std::chrono::steady_clock::now() + IDLE);
                    while (!stop.stop_requested() && !STOP.load() && std::chrono::steady_clock::now() < idle_until) {
                        {
                            std::lock_guard guard(queue_mutex);
                            if (!queue.empty()) {
                                return false;
                            }
                        }
                        pollfd descriptor{fd, POLLIN, 0};
                        auto status = ::poll(&descriptor, 1, SLICE_MS);
                        if (status > 0) {
                            return true;
                        }
                        if (status < 0 && errno != EINTR) {
                            return false;
                        }
                    }
                    return false;
                };
                try {
                    auto caller = peerfs::live::identity(network, job.endpoint);
                    constexpr auto LIFETIME = std::chrono::seconds(60);
                    auto retire = std::chrono::steady_clock::now() + LIFETIME;
                    do {
                        auto body = peerfs::live::receiveFrame(job.connection.get());
                        Json reply;
                        try {
                            reply = handler(caller, body);
                        } catch (const Failure &ERROR) {
                            reply = peerfs::live::refusal(ERROR.code, ERROR.what());
                        } catch (const std::exception &) {
                            reply = peerfs::live::refusal(EINVAL, "invalid request or internal configuration");
                        }
                        peerfs::live::sendFrame(job.connection.get(), reply);
                    } while (waitNext(job.connection.get(), retire));
                } catch (const Failure &ERROR) {
                    try {
                        peerfs::live::sendFrame(job.connection.get(), peerfs::live::refusal(ERROR.code, ERROR.what()));
                    } catch (...) {
                    }
                } catch (const std::exception &) {
                    try {
                        peerfs::live::sendFrame(
                            job.connection.get(),
                            peerfs::live::refusal(EINVAL, "invalid request or internal configuration"));
                    } catch (...) {
                    }
                }
            }
        });
    }
    while (!STOP.load()) {
        pollfd waiting{listener.get(), POLLIN, 0};
        if (::poll(&waiting, 1, 250) <= 0) {
            continue;
        }
        sockaddr_in remote{};
        socklen_t length = sizeof(remote);
        int accepted =
            ::accept4(listener.get(), reinterpret_cast<sockaddr *>(&remote), &length, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (accepted < 0) {
            continue;
        }
        Fd connection(accepted);
        peerfs::live::noDelay(connection.get());
        std::array<char, INET_ADDRSTRLEN> ip{};
        if (!::inet_ntop(AF_INET, &remote.sin_addr, ip.data(), ip.size())) {
            continue;
        }
        {
            std::lock_guard guard(queue_mutex);
            if (queue.size() >= QUEUE_LIMIT) {
                continue;
            }
            queue.push_back(
                Job{std::move(connection), std::string(ip.data()) + ':' + std::to_string(::ntohs(remote.sin_port))});
        }
        ready.notify_one();
    }
    for (auto &worker : workers) {
        worker.request_stop();
    }
    ready.notify_all();
}

std::string randomToken() {
    constexpr std::size_t TOKEN_BYTES = 32;
    std::array<char, TOKEN_BYTES> bytes{};
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        auto count = ::getrandom(bytes.data() + offset, bytes.size() - offset, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw Failure("cannot generate session token");
        }
        offset += static_cast<std::size_t>(count);
    }
    return peerfs::live::encodeHex(std::string_view(bytes.data(), bytes.size()));
}
std::string encodeHex(std::string_view data) {
    constexpr std::string_view DIGITS = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (unsigned char byte : data) {
        result += DIGITS[byte >> 4];
        result += DIGITS[byte & 15];
    }
    return result;
}
std::string decodeHex(std::string_view data) {
    if (data.size() % 2 != 0 || data.size() > MAX_READ * 2) {
        throw Failure("invalid data encoding", EINVAL);
    }
    auto nibble = [](char character) -> unsigned {
        if (character >= '0' && character <= '9') {
            return static_cast<unsigned>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<unsigned>(character - 'a' + 10);
        }
        throw Failure("invalid hex digit", EINVAL);
    };
    std::string result;
    result.reserve(data.size() / 2);
    for (std::size_t index = 0; index < data.size(); index += 2) {
        result += static_cast<char>((nibble(data[index]) << 4) | nibble(data[index + 1]));
    }
    return result;
}

} // namespace peerfs::live
