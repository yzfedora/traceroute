#ifndef _TRACEROUTE_H
#define _TRACEROUTE_H

#define BUFSZ	2048

/*
 * We use this structure to save attributes of traceroute program.
 */
struct traceroute {
	int	ttl_max;	/* max value of TTL	*/
#define TTL_MAX	30		/* default value of TTL	*/
	int	ttl;		/* the current ttl	*/
	int	ret;		/* return value recv()	*/
	unsigned short	sport;	/* local binding port	*/
	unsigned short	dport;	/* destination port	*/
	int	sendsk;		/* an UDP socket	*/
	int	recvsk;		/* ICMP or ICMPV6	*/
	char	*hostname;	/* hostname we to trace	*/
	char	*canonname;	/* canonical name	*/
	char	buf[BUFSZ];	/* buffer of recvfrom()	*/
	ssize_t	nread;		/* length of received	*/
	struct sockaddr_storage	addr;	/* local address for send	*/
	socklen_t		addrlen;
	struct sockaddr_storage peer;	/* peer address	to receive	*/
	socklen_t		peerlen;
	struct timeval		rtt;	/* RTT, as the data to send also.*/
#define PACKET_SZ		(sizeof(struct timeval))

	long (*getrtt)(struct traceroute *tr);
	int (*validity_check)(struct traceroute *tr);
	int (*set_port_and_ttl)(struct traceroute *tr);
	int (*send)(struct traceroute *tr);
	int (*recv)(struct traceroute *tr);
	void (*launch)(struct traceroute *tr);
	void (*delete)(struct traceroute *tr);
};


struct traceroute *traceroute_new(const char *hostname, int ttl);
#endif
