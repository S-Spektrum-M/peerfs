#pragma once

#include <expected>
#include <string>
#include <string_view>

namespace peerfs {

[[nodiscard,
  doc::brief("Run the foreground, non-root tailnet authority; persist monotonically numbered rule snapshots.")]]
std::expected<void, std::string>
serveAuthority(std::string_view network_file, std::string_view rules_file, std::string_view state_directory);

} // namespace peerfs
