/* advanced-logger.cc: Advanced C++ netconsd module with regex filtering
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <inttypes.h>
#include <fstream>
#include <string>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <atomic>
#include <thread>
#include <chrono>

#include <re2/re2.h>

#include <msgbuf-struct.h>
#include <ncrx-struct.h>

#include <jhash.h>

/*
 * The below allows us to index an unordered_map by an IP address.
 */

static bool operator==(const struct in6_addr &lhs, const struct in6_addr &rhs)
{
	return std::memcmp(&lhs, &rhs, 16) == 0;
}

namespace std
{

template <> struct hash<struct in6_addr> {
	std::size_t operator()(struct in6_addr const &s) const
	{
		return jhash2((uint32_t *)&s, sizeof(s) / sizeof(uint32_t),
			      0xbeefdead);
	}
};

} /* namespace std */

/*
 * Basic struct to hold the hostname and the FD for its logfile.
 */
struct logtarget {
	char hostname[INET6_ADDRSTRLEN + 1];
	int fd;

	/*
	 * Resolve the hostname, and open() an appropriately named file to
	 * write the logs into.
	 */
	logtarget(struct in6_addr *src)
	{
		int ret;
		struct sockaddr_in6 sa = {
			.sin6_family = AF_INET6,
			.sin6_port = 0,
		};

		memcpy(&sa.sin6_addr, src, sizeof(*src));
		ret = getnameinfo((const struct sockaddr *)&sa, sizeof(sa),
				  hostname, sizeof(hostname) - 1, NULL, 0,
				  NI_NAMEREQD);
		if (ret) {
			const char *ptr;
			fprintf(stderr, "getnameinfo failed: %s\n",
				gai_strerror(ret));
			ptr = inet_ntop(AF_INET6, src, hostname,
					INET6_ADDRSTRLEN);
			if (ptr == NULL) {
				fprintf(stderr, "inet_ntop failed: %s\n",
					strerror(errno));
				snprintf(hostname, 8, "unknown");
			}
		}

		ret = open(hostname, O_TRUNC | O_WRONLY | O_CREAT, 0644);
		if (ret == -1) {
			fprintf(stderr, "FATAL: open() failed: %m\n");
			abort();
		}

		fd = ret;
	}

	/*
	 * Close the file
	 */
	~logtarget(void)
	{
		close(fd);
	}
};

/*
 * This relates the IP address of the remote host to its logtarget struct.
 */
static std::unordered_map<struct in6_addr, struct logtarget> *maps;

/*
 * Track which hosts we've seen.
 */
static std::vector<std::unordered_set<struct in6_addr> > seen_hosts;

/*
 * Vector to store compiled RE2 regex patterns from netconsd-regexps.txt
 */
static std::vector<std::unique_ptr<RE2> > ignore_patterns;

/*
 * Statistics tracking variables
 */
static std::atomic<uint64_t> messages_received{ 0 };
static std::atomic<uint64_t> messages_dropped{ 0 };
static std::atomic<uint64_t> total_hosts_seen{ 0 };
static std::atomic<bool> stats_thread_running{ false };
static std::thread stats_thread;

/*
 * Load regular expression patterns from netconsd-regexps.txt file
 */
static void load_ignore_patterns(void)
{
	std::ifstream file("/etc/netconsd/netconsd-regexps.txt");
	std::string line;
	bool in_ignore_section = false;

	ignore_patterns.clear();

	if (!file.is_open()) {
		fprintf(stderr,
			"Warning: Could not open netconsd-regexps.txt, no filtering will be applied\n");
		return;
	}

	while (std::getline(file, line)) {
		// Skip empty lines and comments (lines starting with #)
		if (line.empty() || line[0] == '#') {
			continue;
		}

		// Check for ignore section header
		if (line == "ignore:") {
			in_ignore_section = true;
			continue;
		}

		// Check if we're leaving the ignore section (new section or non-indented line)
		if (in_ignore_section && !line.empty() && line[0] != ' ' &&
		    line[0] != '\t' && line[0] != '-') {
			in_ignore_section = false;
		}

		// Process ignore patterns (lines starting with "  - " or "- ")
		if (in_ignore_section && (line.substr(0, 4) == "  - " ||
					  line.substr(0, 2) == "- ")) {
			std::string pattern;
			if (line.substr(0, 4) == "  - ") {
				pattern = line.substr(4);
			} else {
				pattern = line.substr(2);
			}

			// Compile the regular expression
			auto regex = std::make_unique<RE2>(pattern);
			if (!regex->ok()) {
				fprintf(stderr,
					"Warning: Invalid regex pattern '%s': %s\n",
					pattern.c_str(),
					regex->error().c_str());
				continue;
			}

			ignore_patterns.push_back(std::move(regex));
		}
	}

	file.close();
	fprintf(stderr,
		"Loaded %zu ignore patterns from netconsd-regexps.txt\n",
		ignore_patterns.size());
}

/*
 * Check if a log line should be ignored based on loaded regex patterns
 */
static bool should_ignore_line(const char *line)
{
	if (ignore_patterns.empty()) {
		return false;
	}

	for (const auto &pattern : ignore_patterns) {
		if (RE2::PartialMatch(line, *pattern)) {
			return true;
		}
	}

	return false;
}

/*
 * Statistics thread function that outputs statistics every minute
 */
static void stats_thread_func()
{
	auto last_time = std::chrono::steady_clock::now();
	uint64_t last_received = 0;

	while (stats_thread_running) {
		// Sleep in 1-second intervals to allow quick shutdown
		for (int i = 0; i < 60 && stats_thread_running; ++i) {
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		auto current_time = std::chrono::steady_clock::now();
		uint64_t current_received = messages_received.load();
		uint64_t current_dropped = messages_dropped.load();
		uint64_t current_hosts = total_hosts_seen.load();

		// Calculate messages per second over the last minute
		auto time_diff =
			std::chrono::duration_cast<std::chrono::seconds>(
				current_time - last_time)
				.count();
		uint64_t msg_diff = current_received - last_received;
		double messages_per_second =
			(time_diff > 0) ? (double)msg_diff / time_diff : 0.0;

		fprintf(stderr,
			"[STATS] Messages received: %lu, dropped: %lu, hosts seen: %lu, messages/sec: %.2f\n",
			current_received, current_dropped, current_hosts,
			messages_per_second);

		last_time = current_time;
		last_received = current_received;
	}
}

/*
 * Return the existing logtarget struct if we've seen this host before and the
 * message should not be ignored; else, initialize a new logtarget, insert it,
 * and return that. Returns std::nullopt if the message should be ignored.
 */
static std::optional<std::reference_wrapper<logtarget> >
get_target(int thread_nr, struct in6_addr *src, const char *log_text)
{
	// Track if this is a new host
	std::unordered_set<struct in6_addr> &host_set = seen_hosts[thread_nr];
	std::pair<std::unordered_set<struct in6_addr>::iterator, bool>
		seen_result = host_set.insert(*src);
	if (seen_result.second) {
		// Successfully inserted a new host, increment counter
		total_hosts_seen++;
	}

	// Check if message should be filtered
	if (should_ignore_line(log_text)) {
		messages_dropped++;
		return std::nullopt;
	}

	// Only create logtarget (and file) if we pass the filter
	auto itr = maps[thread_nr].find(*src);
	if (itr == maps[thread_nr].end()) {
		itr = maps[thread_nr].emplace(*src, src).first;
	}

	return std::ref(itr->second);
}

/*
 * Actually write the line to the file
 */
static void write_log(struct logtarget &tgt, struct msg_buf *buf,
		      struct ncrx_msg *msg)
{
	if (!msg) {
		/* Legacy style netcons msg */
		dprintf(tgt.fd, "%s\n", buf->buf);
		return;
	}

	/* extended netcons msg with metadata */
	if (std::strlen(msg->version) > 1)
		dprintf(tgt.fd, "%s ", msg->version);
	dprintf(tgt.fd, "%06" PRIu64 " ", msg->seq);
	dprintf(tgt.fd, "%014" PRIu64 " ", msg->ts_usec);
	dprintf(tgt.fd, "%d ", msg->facility);
	dprintf(tgt.fd, "%d ", msg->level);
	if (msg->cont_start)
		dprintf(tgt.fd, "[CONT START] ");
	if (msg->cont)
		dprintf(tgt.fd, "[CONT] ");
	if (msg->oos)
		dprintf(tgt.fd, "[OOS] ");
	if (msg->seq_reset)
		dprintf(tgt.fd, "[SEQ RESET] ");
	dprintf(tgt.fd, "%s\n", msg->text);
}

extern "C" int netconsd_output_init(int nr)
{
	maps = new std::unordered_map<struct in6_addr, struct logtarget>[nr];
	seen_hosts.resize(nr);
	load_ignore_patterns();

	// Start the statistics thread
	stats_thread_running = true;
	stats_thread = std::thread(stats_thread_func);

	return 0;
}

extern "C" void netconsd_output_exit(void)
{
	// Stop the statistics thread
	stats_thread_running = false;
	if (stats_thread.joinable()) {
		stats_thread.join();
	}

	delete[] maps;
	seen_hosts.clear();
}

/*
 * This is the actual function called by netconsd.
 */
extern "C" void netconsd_output_handler(int t, struct in6_addr *src,
					struct msg_buf *buf,
					struct ncrx_msg *msg)
{
	const char *log_text = msg ? msg->text : buf->buf;
	messages_received++;

	/* get_target checks filtering and returns std::nullopt if message should be ignored */
	auto target = get_target(t, src, log_text);
	if (target.has_value()) {
		write_log(target.value(), buf, msg);
	}
}
