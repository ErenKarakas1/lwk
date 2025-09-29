#include "include/common.hpp"
#include "include/cmd.hpp"

#define UTILS_PROCESS_IMPLEMENTATION
#include "include/process.hpp"

#include <array>
#include <charconv>
#include <print>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

using utils::cmd::Command;
using utils::cmd::ParseError;
using utils::cmd::arg;
using utils::process::Redirect;
using utils::process::close_fd;
using utils::process::create_pipe;
using utils::process::run_sync;

namespace {
enum class PortListener: u8 { SS, LSOF };

const std::unordered_map<std::string_view, i32> port_map = {
    {"test", 8080}
};

std::vector<int> get_pids_by_lsof(const std::span<char> buffer) {
    std::vector<int> pids;
    std::istringstream iss(buffer.data());

    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        int pid = 0;
        auto [ptr, ec] = std::from_chars(line.data(), line.data() + line.size(), pid);
        if (ec == std::errc{} && ptr == line.data() + line.size()) {
            pids.push_back(pid);
        }
    }

    return pids;
}

std::vector<int> get_pids_by_ss(const std::span<char> buffer) {
    std::vector<int> pids;
    std::istringstream iss(buffer.data());
    std::string line;

    bool first_line = true;
    while (std::getline(iss, line)) {
        if (first_line) {
            first_line = false;
            continue; // Skip header line
        }
        if (line.empty()) continue;

        // Example line format:
        // LISTEN 0      128          *:8080                     *:*      users:(("myserver",pid=1234,fd=6))
        auto users_pos = line.find("users:");
        if (users_pos == std::string::npos) continue;

        auto pid_pos = line.find("pid=", users_pos);
        if (pid_pos == std::string::npos) continue;
        pid_pos += 4; // Move past "pid="

        auto end_pos = line.find(',', pid_pos);
        if (end_pos == std::string::npos) {
            end_pos = line.find(')', pid_pos);
            if (end_pos == std::string::npos) continue;
        }

        std::string pid_str = line.substr(pid_pos, end_pos - pid_pos);
        int pid = 0;
        auto [ptr, ec] = std::from_chars(pid_str.data(), pid_str.data() + pid_str.size(), pid);
        if (ec == std::errc{} && ptr == pid_str.data() + pid_str.size()) {
            pids.push_back(pid);
        }
    }

    return pids;
}

std::vector<int> get_pids_by_port(const int port, const PortListener listener = PortListener::SS) {
    Fd read_end = INVALID_FD;
    Fd write_end = INVALID_FD;
    if (const auto result = create_pipe(read_end, write_end); !result.has_value()) return {};

    Redirect redirect;
    redirect.fd_out = write_end;

    std::vector<std::string> args;
    switch (listener) {
        case PortListener::SS:      args = {"ss", "-tlnp", "sport", "eq", std::to_string(port)}; break;
        case PortListener::LSOF:    args = {"lsof", "-ti", ":" + std::to_string(port)}; break;
        default:                    UNREACHABLE();
    }

    if (const auto result = run_sync(args, redirect); !result.has_value()) {
        close_fd(read_end);
        return {};
    }

    std::array<char, 4096> buffer{};
    const ssize_t bytes_read = read(read_end, buffer.data(), buffer.size() - 1);
    close_fd(read_end);

    if (bytes_read <= 0) return {};

    auto read_size = static_cast<std::size_t>(bytes_read);
    buffer.at(read_size) = '\0';

    switch (listener) {
        case PortListener::SS:      return get_pids_by_ss({buffer.data(), read_size});
        case PortListener::LSOF:    return get_pids_by_lsof({buffer.data(), read_size});
        default:                    UNREACHABLE();
    }
}

bool kill_processes(const std::vector<int>& pids) {
    bool success = true;

    std::array<std::string, 2> kill_args = {"kill", ""};
    for (int pid : pids) {
        kill_args[1] = std::to_string(pid);
        if (auto result = run_sync(kill_args); !result.has_value()) {
            std::println(stderr, "Error killing process {}: {}", pid, result.error());
            success = false;
        } else {
            std::println("Killed process {}", pid);
        }
    }

    return success;
}
} // namespace

int main(int argc, char* argv[]) {
    const Command app = Command("lwk", "Kill processes by port number or predefined names")
        .arg(arg("-p --port <PORT>")
            .about("Kill processes using the specified port"))
        .arg(arg("<NAME>")
            .about("Kill processes using port mapped to this name")
            .required(false))
        .arg(arg("-h --help")
            .about("Show this help message"));

    auto [matches, err] = app.get_matches(argc, argv);

    if (err != ParseError::None) {
        std::println(stderr, "Error parsing arguments");
        app.print_help();
        return 1;
    }

    if (matches.get_flag("help")) {
        app.print_help();
        return 0;
    }

    // Check for port flag
    if (auto port_opt = matches.get_one<int>("port"); port_opt.has_value()) {
        int port = *port_opt;
        std::println("Looking for processes on port {}...", port);

        auto pids = get_pids_by_port(port);
        if (pids.empty()) {
            std::println("No processes found on port {}", port);
            return 0;
        }

        std::println("Found {} process(es) on port {}", pids.size(), port);
        return kill_processes(pids) ? 0 : 1;
    }

    // Check for name argument
    if (auto name_opt = matches.get_one<std::string>("NAME"); name_opt.has_value()) {
        const std::string& name = *name_opt;

        if (!port_map.contains(name)) {
            std::print(stderr, "Unknown name '{}'. Available names: ", name);
            bool first = true;
            for (const auto& [key, value] : port_map) {
                if (!first) std::print(stderr, ", ");
                std::print(stderr, "{} ({})", key, value);
                first = false;
            }
            std::println(stderr);
            return 1;
        }

        int port = port_map.at(name);
        std::println("Looking for processes on port {} (mapped from '{}')...", port, name);

        auto pids = get_pids_by_port(port);
        if (pids.empty()) {
            std::println("No processes found on port {}", port);
            return 0;
        }

        std::println("Found {} process(es) on port {}", pids.size(), port);
        return kill_processes(pids) ? 0 : 1;
    }

    // No valid arguments provided
    std::println(stderr, "Please specify either -p <port> or <name>");
    app.print_help();
    return 1;
}