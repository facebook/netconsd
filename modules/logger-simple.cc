/* simple-logger.cc: Very simple example C++ netconsd module
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
#include <unordered_map>
#include <inttypes.h>

#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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
	/* legacy non-extended netcons message */
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
