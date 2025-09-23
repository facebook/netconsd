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
#include <unordered_map>
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
 * Vector to store compiled RE2 regex patterns from netconsd-regexps.txt
 */
static std::vector<std::unique_ptr<RE2> > ignore_patterns;

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
 * Return the existing logtarget struct if we've seen this host before; else,
 * initialize a new logtarget, insert it, and return that.
 */
static struct logtarget &get_target(int thread_nr, struct in6_addr *src)
{
	auto itr = maps[thread_nr].find(*src);
	if (itr == maps[thread_nr].end())
		return maps[thread_nr].emplace(*src, src).first->second;

	return itr->second;
}

/*
 * Actually write the line to the file
 */
static void write_log(struct logtarget &tgt, struct msg_buf *buf,
		      struct ncrx_msg *msg)
{
	const char *log_text;

	/* Determine the log text to check against ignore patterns */
	if (!msg) {
		/* legacy non-extended netcons message */
		log_text = buf->buf;
	} else {
		/* extended netcons msg with metadata - check the actual message text */
		log_text = msg->text;
	}

	/* Check if this line should be ignored */
	if (should_ignore_line(log_text)) {
		return;
	}

	/* Write the log line if it's not ignored */
	if (!msg) {
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
	load_ignore_patterns();
	return 0;
}

extern "C" void netconsd_output_exit(void)
{
	delete[] maps;
}

/*
 * This is the actual function called by netconsd.
 */
extern "C" void netconsd_output_handler(int t, struct in6_addr *src,
					struct msg_buf *buf,
					struct ncrx_msg *msg)
{
	struct logtarget &cur = get_target(t, src);
	write_log(cur, buf, msg);
}
