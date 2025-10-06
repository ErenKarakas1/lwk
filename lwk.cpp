#include "include/common.hpp"
#include "include/cli.hpp"

#define UTILS_PROCESS_IMPLEMENTATION
#include "include/process.hpp"

#include <array>
#include <charconv>
#include <expected>
#include <format>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

using utils::cli::Command;
using utils::cli::ParseError;
using utils::cli::arg;
using utils::process::Redirect;
using utils::process::close_fd;
using utils::process::create_pipe;
using utils::process::run_sync;

namespace {
enum class PortListener: u8 { SS, LSOF };

const std::unordered_map<std::string_view, i32> PORT_MAP = {
    {"test", 8080}
};

// Simple string search without <algorithm> header
constexpr const char* find_substring(const char* start, const char* end, const std::string_view pattern) {
    if (pattern.empty() || start >= end) return end;
    
    const std::size_t pattern_len = pattern.size();
    const char* search_end = end - pattern_len + 1;
    
    for (const char* pos = start; pos < search_end; ++pos) {
        bool match = true;
        for (std::size_t i = 0; i < pattern_len; ++i) {
            if (pos[i] != pattern[i]) {
                match = false;
                break;
            }
        }
        if (match) return pos;
    }
    
    return end;
}

std::vector<int> get_pids_by_lsof(const std::span<char> buffer) {
    std::vector<int> pids;
    
    const char* start = buffer.data();
    const char* end = start + buffer.size();

    constexpr auto is_whitespace = [](const char c) {
        return c == ' ' || c == '\t' || c == '\n';
    };
    
    while (start < end) {
        // Skip to next non-whitespace character
        while (start < end && is_whitespace(*start)) ++start;
        if (start >= end) break;
        
        // Find end of current line
        const char* line_end = start;
        while (line_end < end && *line_end != '\n') ++line_end;
        
        int pid = 0;
        auto [ptr, ec] = std::from_chars(start, line_end, pid);
        if (ec == std::errc{} && ptr == line_end) {
            pids.push_back(pid);
        }
        
        start = line_end + 1;
    }

    return pids;
}

std::vector<int> get_pids_by_ss(const std::span<char> buffer) {
    std::vector<int> pids;
    
    const char* start = buffer.data();
    const char* end = start + buffer.size();
    
    // Skip first line (header) and newline
    while (start < end && *start != '\n') ++start;
    if (start < end) ++start;
    
    while (start < end) {
        const char* line_end = start;
        while (line_end < end && *line_end != '\n') ++line_end;
        
        const char* users_pos = find_substring(start, line_end, "users:");
        if (users_pos == line_end) {
            start = line_end + 1;
            continue;
        }
        
        // Look for "pid=" after "users:"
        const char* pid_pos = find_substring(users_pos, line_end, "pid=");
        if (pid_pos == line_end) {
            start = line_end + 1;
            continue;
        }
        pid_pos += 4; // Move past "pid="
        
        // Find end of PID (comma or closing paren)
        const char* pid_end = pid_pos;
        while (pid_end < line_end && *pid_end != ',' && *pid_end != ')') ++pid_end;
        
        int pid = 0;
        auto [ptr, ec] = std::from_chars(pid_pos, pid_end, pid);
        if (ec == std::errc{} && ptr == pid_end) {
            pids.push_back(pid);
        }
        
        start = line_end + 1;
    }

    return pids;
}

std::expected<std::vector<int>, std::string> get_pids_by_port(const int port, const PortListener listener = PortListener::SS) {
    Fd read_end = INVALID_FD;
    Fd write_end = INVALID_FD;
    if (const auto result = create_pipe(read_end, write_end); !result.has_value()) {
        return std::unexpected("Error creating pipe: " + result.error());
    }

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
        close_fd(write_end);
        return std::unexpected(std::format("Error running '{}': {}", args[0], result.error()));
    }

    std::array<char, 4096> buffer{};
    const ssize_t bytes_read = read(read_end, buffer.data(), buffer.size() - 1);
    close_fd(read_end);

    if (bytes_read <= 0) {
        close_fd(write_end);
        return {};
    }

    const auto read_size = static_cast<std::size_t>(bytes_read);
    switch (listener) {
        case PortListener::SS:      return get_pids_by_ss({buffer.data(), read_size});
        case PortListener::LSOF:    return get_pids_by_lsof({buffer.data(), read_size});
        default:                    UNREACHABLE();
    }
}

bool kill_processes(const std::vector<int>& pids) {
    bool all_success = true;

    std::array<std::string, 2> kill_args = {"kill", ""};
    for (const int pid : pids) {
        kill_args[1] = std::to_string(pid);
        if (const auto result = run_sync(kill_args); !result.has_value()) {
            std::println(stderr, "Error killing process {}: {}", pid, result.error());
            all_success = false;
        } else {
            std::println("Killed process {}", pid);
        }
    }

    return all_success;
}

int handle_port(const int port, const PortListener listener, std::string_view source = "") {
    if (!source.empty()) {
        std::println("Looking for processes on port {} (mapped from '{}')...", port, source);
    } else {
        std::println("Looking for processes on port {}...", port);
    }

    const auto pids_result = get_pids_by_port(port, listener);
    if (!pids_result.has_value()) {
        std::println(stderr, "Error retrieving processes on port {}: {}", port, pids_result.error());
        return 1;
    }

    const auto& pids = *pids_result;
    if (pids.empty()) {
        std::println("No processes found on port {}", port);
        return 0;
    }

    std::println("Found {} process(es) on port {}", pids.size(), port);
    return kill_processes(pids) ? 0 : 1;
}
} // namespace

int main(int argc, char* argv[]) {
    const Command app = Command("lwk", "Kill processes by port number or predefined names")
        .arg(arg("--ss")
            .about("Use 'ss' to find processes (default)"))
        .arg(arg("--lsof")
            .about("Use 'lsof' to find processes"))
        .arg(arg("-p --port <PORT>")
            .about("Kill processes using the specified port"))
        .arg(arg("<NAME>")
            .required(false))
        .arg(arg("-h --help")
            .about("Show this help message"));

    auto [matches, err] = app.get_matches(argc, argv);

    if (err.has_error()) {
        std::println(stderr, "Error parsing arguments: {}", err.message);
        app.print_help();
        return 1;
    }

    if (matches.get_flag("help")) {
        app.print_help();
        return 0;
    }

    const PortListener listener = matches.get_flag("lsof") ? PortListener::LSOF : PortListener::SS;

    // Check for port flag
    if (const auto port_opt = matches.get_one<int>("port"); port_opt.has_value()) {
        return handle_port(*port_opt, listener);
    }

    // Check for name argument
    if (const auto name_opt = matches.get_one<std::string>("NAME"); name_opt.has_value()) {
        const std::string& name = *name_opt;

        const auto it = PORT_MAP.find(name);
        if (it == PORT_MAP.end()) {
            std::print(stderr, "Unknown name '{}'. Available names: ", name);
            bool first = true;
            for (const auto& [key, value] : PORT_MAP) {
                if (!first) std::print(stderr, ", ");
                std::print(stderr, "{} ({})", key, value);
                first = false;
            }
            std::println(stderr);
            return 1;
        }

        return handle_port(it->second, listener, name);
    }

    // No valid arguments provided
    std::println(stderr, "Please specify either -p <port> or <name>\n");
    app.print_help();
    return 1;
}