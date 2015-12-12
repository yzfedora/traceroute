/* This is a traceroute program written under the Linux.
 *   		Copyright (C) 2015  Yang Zhang  <yzfedora@gmail.com>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>		/* gettimeofday()		*/
#include <netdb.h>
#include <netinet/ip_icmp.h>	/* 'ICMP_*'			*/
#include <linux/udp.h>		/* 'struct udphdr'		*/
#include <linux/icmpv6.h>	/* 'ICMPV6_*'			*/
#include <linux/ipv6.h>
#include <arpa/inet.h>		/* inet_ntop()			*/
#include <errno.h>
#include "traceroute.h"


#define INIT	__attribute__((constructor))

/*
 * We can't using SIG_IGN to ignore the SIGALRM simply. so we register a
 * signal handelr for SIGALRM, but no anything acutally will be did.
 */
static void sigalrm_handler(int signo) { }

static void INIT sigalrm_register(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigalrm_handler;
	if (sigaction(SIGALRM, &act, NULL) == -1) {
		perror("couldn't ignore the alarm signal");
		exit(EXIT_FAILURE);
	}
}

static void usage(char *progname)
{
	fprintf(stderr,
		"Usage: %s [option] hostname\n"
		"    -m ttl  set the time-to-live field\n"
		"    -h      dispaly help info\n",
		progname);
	exit(EXIT_FAILURE);
}

/*
 * Parsing the arguments, set the ttl and return the hostname according the
 * option.
 */
static char *parsing_args(int argc, char **argv, int *ttl)
{
	int opt;

	*ttl = 0;
	while ((opt = getopt(argc, argv, "m:h")) != -1) {
		switch (opt) {
		case 'm':
			*ttl = atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}

	if (optind != argc - 1)
		usage(argv[0]);

	return argv[optind];
}

static int bind_by_port(int sk, int family, int sport)
{
	struct sockaddr_storage ss = { 0 };
	socklen_t len;

	ss.ss_family = family;
	switch (ss.ss_family) {
	case AF_INET:
		((struct sockaddr_in *)&ss)->sin_port = htons(sport);
		len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)&ss)->sin6_port = htons(sport);
		len = sizeof(struct sockaddr_in6);
		break;
	default:
		return -1;
	}

	return bind(sk, (struct sockaddr *)&ss, len);
}

static int set_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		perror("fcntl - F_GETFL");
		return -1;
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		perror("fcntl - F_SETFL");
		return -1;
	}

	return 0;
}

/*
 * To prevent the signal race when receiving data from the socket. we decided
 * to use pselect() to prevent it. and set the socket to NONBLOCK.
 */
static int icmp_create(int family)
{
	int sk = -1;
	int proto;

	if (family == AF_INET)
		proto = IPPROTO_ICMP;
	else if (family == AF_INET6)
		proto = IPPROTO_ICMPV6;
	else
		goto out;

	if ((sk = socket(family, SOCK_RAW, proto)) == -1)
		goto out;

	if (set_nonblock(sk) == -1)
		goto out;

	return sk;
out:
	if (sk >= 0)
		close(sk);
	return -1;
}

/*
 * Dynamically increment the port of destination host. prevention the port
 * of destination has been used.
 */
static int traceroute_set_port_and_ttl_v4(struct traceroute *tr)
{
	int err = 0;
	
	((struct sockaddr_in *)&tr->addr)->sin_port = htons(++tr->dport);

	if ((err = setsockopt(tr->sendsk, IPPROTO_IP, IP_TTL, &tr->ttl,
		       sizeof(tr->ttl))) == -1)
		perror("setsockopt");

	return err;
}

static int traceroute_set_port_and_ttl_v6(struct traceroute *tr)
{
	int err = 0;

	((struct sockaddr_in6 *)&tr->addr)->sin6_port = htons(++tr->dport);	
	if ((err = setsockopt(tr->sendsk, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			      &tr->ttl, sizeof(tr->ttl))) == -1)
		perror("setsockopt");

	return err;
}

static int traceroute_send(struct traceroute *tr)
{
	tr->ret = -1;

	if (tr->set_port_and_ttl(tr) == -1)
		goto out;

	/* Save the current time, that data be send. */
	if (gettimeofday(&tr->rtt, NULL) == -1) {
		perror("getimeofday");
		goto out;
	}

	/*
	 * Just send a timeval structure by using UDP to peer host.
	 * we don't check in the case of return value >= 0 but < PACKET_SZ.
	 */
	if ((tr->ret = sendto(tr->sendsk, &tr->rtt, PACKET_SZ, 0,
			      (struct sockaddr *)&tr->addr,
			      tr->addrlen)) != PACKET_SZ) {
		perror("sendto");
		goto out;
	}

out:
	return tr->ret;
}

/* 
 * Needn't any more, we don't send ICMP packet.
 */
/*static unsigned short traceroute_chksum(void *buf, int len)
{
	int sum = 0;
	int nleft = len;
	unsigned short *p = buf;

	while (nleft > 0) {
		sum += *p++;
		nleft -= 2;
	}

	if (nleft == 1)
		sum += *((unsigned char *)p);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~((unsigned short)sum);
}*/

/*
 * Convert the address info in the structure 'sockaddr' to a string. and
 * return a string which was allocated by calloc(). should free() it later.
 */
static char *str_addr(struct sockaddr *sa)
{
	char *str = calloc(1, INET6_ADDRSTRLEN);
	void *addr;

	switch (sa->sa_family) {
	case AF_INET:
		addr = &((struct sockaddr_in *)sa)->sin_addr;
		break;
	case AF_INET6:
		addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
		break;
	default:
		errno = -EAFNOSUPPORT;
		goto out;
	}

	if (inet_ntop(sa->sa_family, addr, str, INET6_ADDRSTRLEN) == NULL)
		strerror_r(errno, str, sizeof(INET6_ADDRSTRLEN));

out:
	return str;
}

/*
 * Lookup the offical canonical name by given the structure 'sockaddr'(if
 * it haven't any offical domain name, then the string of IP address shall
 * be returned). otherwise,return NULL on failure.
 */
static char *str_canonical_name(struct sockaddr *sa, socklen_t len)
{
	char *hostname = malloc(NI_MAXHOST);

	if (!hostname)
		goto out;

	/* Ignore the error returned by getnameinfo(). */
	if (getnameinfo(sa, len, hostname, NI_MAXHOST, NULL, 0, 0) != 0)
		goto out;

	return hostname;
out:
	if (hostname)
		free(hostname);
	return NULL;
}

static int address_check(struct traceroute *tr)
{
	struct sockaddr *sa = (struct sockaddr *)&tr->peer;

	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
		return -1;
	return 0;
}

/*
 * Return ICMP_TIME_EXCEEDED， if it's a ICMP time exceeded message caused by
 * packets we sent. or ICMP_DEST_UNREACH be returned, if the packet reached
 * peer host, but port closed. otherwise, -1 returned.
 */
static int traceroute_validity_check_v4(struct traceroute *tr)
{
	tr->ret = -1;

	if (address_check(tr) == -1)
		goto out;

	int len = tr->nread;
	struct iphdr *ip1 = (struct iphdr *)tr->buf;
	int iplen1 = ip1->ihl << 2;
	
	if ((len -= iplen1) < 8)	/* 8 bytes ICMP Header. */
		goto out;

	struct icmphdr *icmp = (struct icmphdr *)(tr->buf + iplen1);
	if ((len -= 8) < 20)		/* minimum IP Header 20, max 60. */
		goto out;

	struct iphdr *ip2 = (struct iphdr *)(tr->buf + iplen1 + 8);
	if ((len -= 20) < 8)		/* 64 bits original datagram's data. */
		goto out;

	struct udphdr *udp = (struct udphdr *)(tr->buf + iplen1 + 8 +
					(ip2->ihl << 2));

	if ((ip2->protocol != IPPROTO_UDP) ||
	    (ntohs(udp->source) != tr->sport) ||
	    (ntohs(udp->dest) != tr->dport))
		goto out;

	/*
	 * Authenticates the type of ICMP.
	 */
	if ((icmp->type == ICMP_TIME_EXCEEDED) &&
	    (icmp->code == ICMP_EXC_TTL))
		tr->ret = ICMP_TIME_EXCEEDED;
	else if ((icmp->type == ICMP_DEST_UNREACH) &&
		 (icmp->code == ICMP_PORT_UNREACH))
		tr->ret = ICMP_PORT_UNREACH;

out:
	return tr->ret;
}

static int traceroute_validity_check_v6(struct traceroute *tr)
{
	tr->ret = -1;

	if (address_check(tr) == -1)
		goto out;

	int len = tr->nread;
	if (len < 8)		/* ICMPv6 at least need 8 bytes. */
		goto out;
	struct icmp6hdr *icmp6 = (struct icmp6hdr *)tr->buf;

	if ((len -= 8) < 40)
		goto out;	/* IPv6 Headers at least 40 bytes. */
	struct ipv6hdr *ipv6 = (struct ipv6hdr *)(tr->buf + 8);

	if ((len -= sizeof(*ipv6)) < 8)
		goto out;	/* first 64-bits data from the upper layer. */
	struct udphdr *udp = (struct udphdr *)(tr->buf + 8 + (sizeof(*ipv6)));
	
	if ((ipv6->nexthdr != IPPROTO_UDP) ||
	    (ntohs(udp->source) != tr->sport) ||
	    (ntohs(udp->dest) != tr->dport))
		goto out;

	/*
	 * Authenticates the type of ICMPV6.
	 */
	if ((icmp6->icmp6_type == ICMPV6_TIME_EXCEED) &&
	    (icmp6->icmp6_code == ICMPV6_EXC_HOPLIMIT))
		tr->ret = ICMP_TIME_EXCEEDED;
	else if ((icmp6->icmp6_type == ICMPV6_DEST_UNREACH) &&
	         (icmp6->icmp6_code == ICMPV6_PORT_UNREACH))
		tr->ret = ICMP_PORT_UNREACH;
out:
	return tr->ret;
}

static char *str_dst_addr(struct sockaddr *sa, socklen_t len)
{
#define STR_DST_ADDR_SZ	(NI_MAXHOST + INET6_ADDRSTRLEN)
	char *str = malloc(STR_DST_ADDR_SZ);
	char *p1;
	char *p2;

	if (str == NULL)
		return "* * * (* * *)";

	p1 = str_canonical_name(sa, len);
	p2 = str_addr(sa);

	snprintf(str, STR_DST_ADDR_SZ, "%s (%s)", p1 ? p1 : "* * *",
						p2 ? p2 : "* * *");
	free(p1);
	free(p2);
	return str;
}

/*
 * Return the Round Trip Time in milliseconds.
 */
static long traceroute_getrtt(struct traceroute *tr)
{
	return (tr->rtt.tv_sec * 1000000 + tr->rtt.tv_usec);
}

/*
 * The return value will be stored in the 'tr->ret' field.
 */
static int traceroute_recv(struct traceroute *tr)
{
	struct timeval now;
	fd_set rset;
	sigset_t new, old;

	tr->ret = -1;	/* validity_check() will set 'ret' field correctly. */
	
	FD_ZERO(&rset);
	FD_SET(tr->recvsk, &rset);
	
	if (sigprocmask(SIG_BLOCK, &new, &old) == -1) {
		perror("sigprocmask");
		goto out;
	}

	alarm(5);	/* Time wait for receipt */
	for ( ;; ) {
		if (pselect(tr->recvsk + 1, &rset, NULL, NULL,
			    NULL, &old) == -1) {
			if (errno == EINTR)
				break;
			perror("pselect");
			goto out;
		}

		if (FD_ISSET(tr->recvsk, &rset)) {
			/* Result-Value parameter */
			tr->peerlen = sizeof(tr->peer);
			tr->nread = recvfrom(tr->recvsk, tr->buf,
					     sizeof(tr->buf), 0,
				             (struct sockaddr *)&tr->peer,
				             &tr->peerlen);
			
			if (gettimeofday(&now, NULL) == -1)
				continue;

			if (tr->nread == -1
			    && errno != EWOULDBLOCK
			    && errno != EAGAIN) {
				perror("recvfrom");
				continue;
			}

			/* 
			 * Return -1 on not a valid packet, or
			 * ICMP_TIME_EXCEEDED on TTL be zero. or
			 * ICMP_PORT_UNREACH when probe have reached.
			 */
			if (tr->validity_check(tr) != -1) {
				timersub(&now, &tr->rtt, &tr->rtt);
				break;
			}
			
		}

	}
out:
	alarm(0);
	return tr->ret;
}

static void print_dst_addr(struct traceroute *tr)
{
	char *str = str_dst_addr((struct sockaddr *)&tr->addr, tr->addrlen);

	printf("traceroute to %s, %d hops max, %ld bytes packets\n",
					str, tr->ttl_max, (long)PACKET_SZ);
	free(str);
}

static void print_dst_addr2(struct traceroute *tr)
{
	char *str = str_dst_addr((struct sockaddr *)&tr->peer, tr->peerlen);

	printf(" %s ", str);
	free(str);
}


/*
 * Send 3 probes to the destination host, if the probes reachs the host or any
 * error is happened, 1 will be returned. otherwise, return 0. (also, the
 * address of probe reached and the rtt/2 will be printed too)
 */
static int probe_launch(struct traceroute *tr)
{
	int i = 0;
	int first = 1;
	int nprobe = 3;
	int done = 0;

	for ( ; i < nprobe; i++) {
		if (tr->send(tr) == -1)
			done = 1;

		/*
		 * 'tr->ret' will indicates the errors, but just ignore.
		 */
		tr->recv(tr);
		
		/*
		 * After success call to recv(), the peer
		 * address will store in traceroute structure.
		 */
		if (first && tr->ret != -1) {
			print_dst_addr2(tr);
			first = 0;
		}

		if (!first) {
			if (tr->ret != -1)
				printf(" %.3f ms ", tr->getrtt(tr) / 2000.0);
			else
				printf(" * ms ");
		}

		if (tr->ret == ICMP_PORT_UNREACH)
			done = 1;
	}

	if (first)
		printf("* * *");

	return done;
}

static void traceroute_launch(struct traceroute *tr)
{
	int done = 0;

	print_dst_addr(tr);

	for ( ; tr->ttl <= tr->ttl_max && !done; tr->ttl++) {
		printf("%2d ", tr->ttl);

		done = probe_launch(tr);
		printf("\n");
	}
}

/*
 * Use the hostname to create a UDP socket, which use to send specified TTL
 * field to the host. and binding the port to the localhost.
 */
static int traceroute_new_impl(struct traceroute *tr)
{
	struct addrinfo hints, *res, *ai;
	int err;
	int ret = -1;
	int sk;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_CANONNAME;

	if ((err = getaddrinfo(tr->hostname, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		goto out;
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		if ((sk = socket(ai->ai_family, ai->ai_socktype,
				 ai->ai_protocol)) == -1)
			continue;
	
		/*
		 * We use a wrapper function for binding to the local port.
		 */
		if (bind_by_port(sk, ai->ai_family, tr->sport) == 0)
			break;

		close(sk);
	}


	/* 
	 * If no any success socket was create, errno set to 0, and return -1.
	 */
	if (ai == NULL) {
		fprintf(stderr, "No more available addrinfo structure for"
				" use\n");
		errno = 0;
		goto out;
	}

	/*
	 * We'll using the sockaddr{in|in6} structure to dynamically change the
	 * port of destination. and use this port to differentiate the sequence
	 * number. it will return in the ICMP error.(caused by Destination port
	 * unreachable or Timedout)
	 */
	memcpy(&tr->addr, ai->ai_addr, ai->ai_addrlen);
	tr->addrlen = ai->ai_addrlen;
	tr->canonname = strdup(ai->ai_canonname);
	tr->sendsk = sk;

	if ((tr->recvsk = icmp_create(ai->ai_family)) == -1)
		goto out;

	ret = 0;
out:
	if (res)
		freeaddrinfo(res);
	return ret;
}

static void traceroute_delete(struct traceroute *tr)
{
	if (tr) {
		free(tr->hostname);
		free(tr->canonname);
		close(tr->sendsk);
		close(tr->recvsk);
	}

	free(tr);
}

struct traceroute *traceroute_new(const char *hostname, int ttl_max)
{
	struct traceroute *tr = calloc(1, sizeof(*tr));

	if (NULL == tr)
		return NULL;

	tr->ttl = 1;				/* initial ttl to start */
	tr->ttl_max = (ttl_max > 0) ? ttl_max : TTL_MAX;
	tr->sport = getpid() | 0x8000;
	tr->dport = 0x8000;			/* Prevent reserve port used */
	tr->hostname = strdup(hostname);	/* Need to free it */
	tr->getrtt = traceroute_getrtt;
	tr->send = traceroute_send;
	tr->recv = traceroute_recv;
	tr->launch = traceroute_launch;
	tr->delete = traceroute_delete;
	
	if (traceroute_new_impl(tr) == -1)
		goto out;

	if (tr->addr.ss_family == AF_INET) {
		tr->validity_check = traceroute_validity_check_v4;
		tr->set_port_and_ttl = traceroute_set_port_and_ttl_v4;
	} else if (tr->addr.ss_family == AF_INET6) {
		tr->validity_check = traceroute_validity_check_v6;
		tr->set_port_and_ttl = traceroute_set_port_and_ttl_v6;
	} else {
		goto out;
	}

	return tr;
out:
	tr->delete(tr);
	return NULL;
}


int main(int argc, char *argv[])
{
	int ttl = 0;
	char *hostname = parsing_args(argc, argv, &ttl);
	struct traceroute *tr = traceroute_new(hostname, ttl);
	
	if (!tr) {
		fprintf(stderr, "Couldn't create object traceroute.\n");
		return 1;
	}

	if (setvbuf(stdout, NULL, _IONBF, 0)) {
		fprintf(stderr, "Unable switch stdout to no buffer mode.\n");
		return 2;
	}

	tr->launch(tr);
	tr->delete(tr);
	return 0;
}
