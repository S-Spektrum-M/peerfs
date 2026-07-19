#pragma once

#include <expected>
#include <string>
#include <string_view>

namespace peerfs {

[[nodiscard,
  doc::brief("Run the foreground, non-root tailnet authority; persist monotonically numbered rule snapshots.")]]
std::expected<void, std::string>
serveAuthority(std::string_view network_file, std::string_view rules_file, std::string_view state_directory);
[[nodiscard, doc::brief("Run the foreground, non-root tailnet exporter with pinned owner-local ceilings.")]]
std::expected<void, std::string> serveExporter(std::string_view network_file, std::string_view node_file);
[[nodiscard, doc::brief("Query the authenticated authority's current rules version and availability.")]]
std::expected<std::string, std::string> authorityStatus(std::string_view network_file);
[[nodiscard,
  doc::brief("Submit this device's topology for fresh admission; return the JSON response, including refusals.")]]
std::expected<std::string, std::string>
admitDevice(std::string_view network_file, std::string_view topology_file, std::string_view home);
[[nodiscard, doc::brief("Freshly admit and foreground-mount one selected export read-only with single-threaded FUSE.")]]
std::expected<void, std::string> mountExport(std::string_view network_file,
                                             std::string_view topology_file,
                                             std::string_view home,
                                             std::string_view export_name);

} // namespace peerfs
