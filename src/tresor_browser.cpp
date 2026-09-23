#include "tresor_login.hpp"

#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// Opening the person's browser on the login URL (specs/002). The URL goes to the program as ONE argv
// element, never through a shell; `BROWSER` (set by whoever started the process, not by SQL) replaces
// the platform's opener. Failing to start a browser is not an error: the URL is printed as well.

namespace duckdb {
namespace tresor {

namespace {

//! `BROWSER` may carry arguments ("firefox --new-window"): split on whitespace, no shell semantics.
std::vector<std::string> SplitCommand(const std::string &command) {
	std::vector<std::string> out;
	std::string current;
	for (char c : command) {
		if (c == ' ' || c == '\t') {
			if (!current.empty()) {
				out.push_back(current);
				current.clear();
			}
		} else {
			current.push_back(c);
		}
	}
	if (!current.empty()) {
		out.push_back(current);
	}
	return out;
}

#ifndef _WIN32
bool Spawn(std::vector<std::string> argv) {
	// argv is built before the fork: the child only execs (or exits), nothing that could take a lock
	// another thread of this process held at the fork
	std::vector<char *> args;
	for (auto &arg : argv) {
		args.push_back(&arg[0]);
	}
	args.push_back(nullptr);
	// the browser's own chatter must not land in the query's output (`duckdb -csv ... > out.csv`)
	auto devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
	auto pid = fork();
	if (pid < 0) {
		if (devnull >= 0) {
			close(devnull);
		}
		return false;
	}
	if (pid == 0) {
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
		}
		execvp(args[0], args.data());
		_exit(127);
	}
	if (devnull >= 0) {
		close(devnull);
	}
	// reaped in the background: the login does not wait for the browser, and no zombie stays behind
	std::thread([pid] {
		int status;
		waitpid(pid, &status, 0);
	}).detach();
	return true;
}
#endif

} // namespace

bool CanOpenBrowser() {
	if (std::getenv("BROWSER")) {
		return true;
	}
#if defined(_WIN32)
	return true;
#elif defined(__APPLE__)
	// over SSH the browser would open on the machine's screen, not in front of the person
	return !std::getenv("SSH_CONNECTION") && !std::getenv("SSH_TTY");
#else
	return std::getenv("DISPLAY") || std::getenv("WAYLAND_DISPLAY");
#endif
}

bool OpenBrowser(const std::string &url) {
	// only a web URL is ever handed to an opener: ShellExecute / open / xdg-open would run a file too
	if (url.rfind("https://", 0) != 0 && url.rfind("http://", 0) != 0) {
		return false;
	}
#ifdef _WIN32
	auto browser = std::getenv("BROWSER");
	int wide_size = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
	std::wstring wide_url(wide_size, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, &wide_url[0], wide_size);
	auto command = browser && *browser ? SplitCommand(browser) : std::vector<std::string>();
	if (!command.empty()) {
		// the program, then its own arguments and the URL - quoted, as one parameter string
		std::string parameters;
		for (size_t i = 1; i < command.size(); i++) {
			parameters += "\"" + command[i] + "\" ";
		}
		parameters += "\"" + url + "\"";
		auto widen = [](const std::string &text) {
			int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
			std::wstring out(size, L'\0');
			MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &out[0], size);
			return out;
		};
		auto program = widen(command[0]);
		auto wide_parameters = widen(parameters);
		return reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", program.c_str(), wide_parameters.c_str(),
		                                               nullptr, SW_SHOWNORMAL)) > 32;
	}
	return reinterpret_cast<INT_PTR>(
	           ShellExecuteW(nullptr, L"open", wide_url.c_str(), nullptr, nullptr, SW_SHOWNORMAL)) > 32;
#else
	std::vector<std::string> argv;
	auto browser = std::getenv("BROWSER");
	if (browser && *browser) {
		argv = SplitCommand(browser);
	}
	if (argv.empty()) {
#ifdef __APPLE__
		argv = {"open"};
#else
		argv = {"xdg-open"};
#endif
	}
	argv.push_back(url);
	return Spawn(std::move(argv));
#endif
}

} // namespace tresor
} // namespace duckdb
