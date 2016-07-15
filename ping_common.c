#include "ping_common.h"
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <math.h>
//daveti: using libnl
#include <netlink/route/neighbour.h>

//daveti: timing metrics for big rtt value - workaround for arpsec
#define NCPING_ARPSEC_RTT_THRESHOLD	10000 // 10ms
#define NCPING_ARPSEC_SLEEP_TIME	5     // 5s
#define NCPING_NDP_SOCK_IF_NAME		"eth1"
#define NCPING_ARPSEC_NETLINK_ATTR_BUF_LEN	512

//#define CLEARWITHOUTSYS	0 // if not defined, use system(DELETE_NEIGH_CMD) call
#define DELETE_NEIGH_CMD	"ip neigh del 2001:db8:0:100:38cb:35b9:7394:ca34 dev eth1"

int options;

int mark;
int sndbuf;
int ttl;
int rtt;
int rtt_addend;
__u16 acked;

struct rcvd_table rcvd_tbl;

/* daveti: for arpsec ncping */
long nreceived_arpsec;
long nrepeats_arpsec;
long tmin_arpsec = LONG_MAX;
long tmax_arpsec;
long long tsum_arpsec;
long long tsum2_arpsec;

/* counters */
long npackets;			/* max packets to transmit */
long nreceived;			/* # of packets we got back */
long nrepeats;			/* number of duplicates */
long ntransmitted;		/* sequence # for outbound packets = #sent */
long nchecksum;			/* replies with bad checksum */
long nerrors;			/* icmp errors */
int interval = 1000;		/* interval between packets (msec) */
int preload;
int deadline = 0;		/* time to die */
int lingertime = MAXWAIT*1000;
struct timeval start_time, cur_time;
volatile int exiting;
volatile int status_snapshot;
int confirm = 0;
volatile int in_pr_addr = 0;	/* pr_addr() is executing */
jmp_buf pr_addr_jmp;

/* Stupid workarounds for bugs/missing functionality in older linuces.
 * confirm_flag fixes refusing service of kernels without MSG_CONFIRM.
 * i.e. for linux-2.2 */
int confirm_flag = MSG_CONFIRM;
/* And this is workaround for bug in IP_RECVERR on raw sockets which is present
 * in linux-2.2.[0-19], linux-2.4.[0-7] */
int working_recverr;

/* timing */
int timing;			/* flag to do timing */
long tmin = LONG_MAX;		/* minimum round trip time */
long tmax;			/* maximum round trip time */
/* Message for rpm maintainers: have _shame_. If you want
 * to fix something send the patch to me for sanity checking.
 * "sparcfix" patch is a complete non-sense, apparenly the person
 * prepared it was stoned.
 */
long long tsum;			/* sum of all times, for doing average */
long long tsum2;
int  pipesize = -1;

int datalen = DEFDATALEN;

char *hostname;
int uid;
uid_t euid;
int ident;			/* process id to identify our packets */

static int screen_width = INT_MAX;

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))

#ifdef CAPABILITIES
static cap_value_t cap_raw = CAP_NET_RAW;
static cap_value_t cap_admin = CAP_NET_ADMIN;
#endif

/* daveti: clear the neighbor cache given the IPv6 */
static int ncping_clear_neigh_cache(int nl_sock, char *ip)
{
#ifdef CLEARWITHOUTSYS

	/* libnl accomplishes this via: rtnl_neigh_delete (can we avoid libnl?)
	 * args = struct nl_sock *sk; struct rtnl_neigh *neigh; int flags; */

	/* FOR REFERENCE: a ndmsg struct contains the following:
	 *	unsigned char ndm_family;
	 *	int           ndm_ifindex;  // Interface index
	 *	__u16         ndm_state;    // State
 	 *	__u8          ndm_flags;    // Flags
	 *	__u8          ndm_type;
	 * FOR REFERENCE: a nlmsghdr struct contains the following:
	 *	__u32 nlmsg_len;    // Length of message including header.
	 *	__u16 nlmsg_type;   // Type of message content.
	 *	__u16 nlmsg_flags;  // Additional flags.
	 *	__u32 nlmsg_seq;    // Sequence number.
	 *	__u32 nlmsg_pid;    // PID of the sending process. */

	/* FOR REFERENCE: a msghdr struct contains the following:
	 *	void         *msg_name;       // optional address
	 *	socklen_t     msg_namelen;    // size of address
	 *	struct iovec *msg_iov;        // scatter/gather array
	 *	size_t        msg_iovlen;     // # elements in msg_iov
	 *	void         *msg_control;    // ancillary data, see below
	 *	size_t        msg_controllen; // ancillary data buffer len
	 *	int           msg_flags;      // flags on received message */
		
	struct {
                struct nlmsghdr         nlhdr;
                struct ndmsg            msg;
                char                    buf[256];
        } req; // this sort of construction implemented by iproute2
	memset(&req, 0, sizeof(req));

	// struct nlmsghdr *nlhdr; 

	/* struct ndmsg msg = {
		.ndm_family = AF_INET6,
		.ndm_ifindex = if_nametoindex("eth1"), // specify interface
		.ndm_flags = 0,
		.ndm_state = NUD_PERMANENT, //| NUD_REACHABLE,
		.ndm_type = 0,
	}; // this sort of construction implemented by libnl */

	req.msg.ndm_family = AF_INET6;
	req.msg.ndm_ifindex = if_nametoindex(NCPING_NDP_SOCK_IF_NAME); // specify inteface
	req.msg.ndm_flags = 0;
	req.msg.ndm_state = NUD_PERMANENT;
	req.msg.ndm_type = 0;

	struct sockaddr_nl *nl_sock_addr;
	socklen_t nl_len = sizeof(struct sockaddr_nl);
	struct msghdr hdr = {
                .msg_namelen = sizeof(struct sockaddr_nl), 
        };
	// struct sockaddr_in6 *possible_match;
	char tgt_buf[sizeof(struct in6_addr)];
	struct iovec iov;
	struct sockaddr_nl header_name = {
		.nl_family = AF_NETLINK,
		.nl_pad = 0,
		.nl_pid = 0,
		.nl_groups = 0,
	};

	/* struct rtattr dest_ip = {
		.rta_len = 20, // two shorts for rtattr, followed by 16 bytes of ipaddr
		.rta_type = NDA_DST, // DESTINATION IP
	};
	struct rtattr dest_ll = {
		.rta_len = 10, // two shorts for rtattr, followed by 6 bytes of lladdr
		.rta_type = NDA_LLADDR, // LINK ADDRESS
	}; */

	int dblCheck;

	nl_sock_addr = malloc(sizeof(*nl_sock_addr));
	if (!nl_sock_addr) {
		perror("malloc failed for sockaddr_nl");
		return -1;
	}
	memset(nl_sock_addr, 0, sizeof(*nl_sock_addr));

	dblCheck = getsockname(nl_sock, (struct sockaddr *)nl_sock_addr, &nl_len);
	printf("ping_common.c | getsockname returned: %i\n", dblCheck);
	hdr.msg_name = &header_name; // place the socket addr corresponding to nl_sock; void * cast not in iproute

	printf("Debug: UID = %i, EUID = %i\n", getuid(), geteuid());

	// printf("ping_common.c | the ifindex of ndmsg is: %i\n", msg.ndm_ifindex); // manually set this
	printf("ping_common.c | the ifindex of ndmsg is: %i\n", req.msg.ndm_ifindex); // manually set this
	
	/* nlhdr = malloc(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ndmsg))) + RTA_ALIGN(dest_ip.rta_len) + RTA_ALIGN(dest_ll.rta_len));
	// nlhdr = malloc(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ndmsg))) + RTA_ALIGN(dest_ip.rta_len));

	if (!nlhdr) {
		perror("malloc failed for nlmsghdr");
		return -1;
	}
	memset(nlhdr, 0, sizeof(*nlhdr));
	
	nlhdr->nlmsg_type = RTM_DELNEIGH;
	nlhdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlhdr->nlmsg_pid = 0; // as per man page, setting nlmsg_pid = 0 for kernel communication
	// nlhdr->nlmsg_pid = nl_sock_addr->nl_pid;
	nlhdr->nlmsg_seq = seqNo; // sequence number; dd (unique) gets incremented each time before clear is called */

	req.nlhdr.nlmsg_type = RTM_DELNEIGH;
	req.nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlhdr.nlmsg_pid = 0;
	req.nlhdr.nlmsg_seq = time(NULL); // chose to use time for the sequence number (unique)	

	// At this point, header is almost complete, but missing nlmsg_len and attachment to payload (ndmsg)
	// gotta memcpy this stuff into da HDR

	// nlhdr->nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ndmsg))) + RTA_ALIGN(dest_ip.rta_len) + RTA_ALIGN(dest_ll.rta_len); 	
	// nlhdr->nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ndmsg))) + RTA_ALIGN(dest_ip.rta_len);
	req.nlhdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	// memcpy(NLMSG_DATA(nlhdr), (void *) &msg, sizeof(struct ndmsg));
	// memcpy((char *)nlhdr + NLMSG_LENGTH(0), &msg, sizeof(struct ndmsg));
	
	/* printf("*** nlmsghdr: len %u, type %u, flags %u, seq %u, pid %u\n", nlhdr->nlmsg_len, 
nlhdr->nlmsg_type, nlhdr->nlmsg_flags, nlhdr->nlmsg_seq, nlhdr->nlmsg_pid);
	printf("*** ndmsg   : fam %u, ifindex %i, flags %u, state %u, type %u\n", msg.ndm_family, msg.ndm_ifindex, msg.ndm_flags, msg.ndm_state, msg.ndm_type); */

	/* struct {
		struct rtattr	metadata;
		unsigned char	payload[sizeof(struct in6_addr)];
	} rtattr_ip_packed;
	memset(&rtattr_ip_packed, 0, sizeof(rtattr_ip_packed)); */

	/* if (inet_pton(AF_INET6, ip, rtattr_ip_packed.payload) <= 0)
		printf("ping_common.c | Failed parsing of ip address\n"); */
	if (inet_pton(AF_INET6, ip, tgt_buf) <= 0)
		printf("ping_common.c | Failed parsing of ip address\n");

	struct rtattr *rta;
	rta = (struct rtattr *) (((void *) (&req.nlhdr)) + NLMSG_ALIGN((&req.nlhdr)->nlmsg_len)); // NLMSG_TAIL
	rta->rta_type = NDA_DST;
	rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
	memcpy(RTA_DATA(rta), tgt_buf, sizeof(struct in6_addr)); 
	req.nlhdr.nlmsg_len = NLMSG_ALIGN(req.nlhdr.nlmsg_len) + RTA_ALIGN(rta->rta_len);
	/* rtattr_ip_packed.metadata = dest_ip;
	memcpy(NLMSG_DATA(nlhdr) + sizeof(struct ndmsg), (void *) &rtattr_ip_packed, dest_ip.rta_len); */

	printf("*** nlmsghdr: len %u, type %u, flags %u, seq %u, pid %u\n", 
req.nlhdr.nlmsg_len, req.nlhdr.nlmsg_type, req.nlhdr.nlmsg_flags, req.nlhdr.nlmsg_seq, req.nlhdr.nlmsg_pid);
	printf("*** ndmsg   : fam %u, ifindex %i, flags %u, state %u, type %u\n", 
req.msg.ndm_family, req.msg.ndm_ifindex, req.msg.ndm_flags, req.msg.ndm_state, req.msg.ndm_type);

	/* struct {
		struct rtattr metadata;
		unsigned char	payload[6];
	} rtattr_ll_packed;
	memset(&rtattr_ll_packed, 0, sizeof(rtattr_ll_packed));
	rtattr_ll_packed.metadata = dest_ll;
	// insert hex entries corresponding to the LL Address into rtattr_ll_packed_payload; removed
	memcpy(NLMSG_DATA(nlhdr) + sizeof(struct ndmsg) + dest_ip.rta_len, (void *) &rtattr_ll_packed, dest_ll.rta_len); */

	iov.iov_base = (void *) &req.nlhdr;
	iov.iov_len = req.nlhdr.nlmsg_len;

	int i;
	unsigned char *ptr = (unsigned char *)iov.iov_base;
	for (i = 0; i < iov.iov_len; i++) {
		printf("%x ", ptr[i]);
	}
	printf("\n");

	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1; // number of elements in iovec

	struct sockaddr_nl * testname = (struct sockaddr_nl *)hdr.msg_name;
        printf("*** msghdr  : name : family %i, pad %i, pid %i, groups %u\n", 
testname->nl_family, testname->nl_pad, testname->nl_pid, testname->nl_groups);	
	if (hdr.msg_control == NULL)
		printf("***         : control is NULL as expected\n");
	else
		printf("***         : control is NOT NULL\n");
	printf("***         : namelen %i, iov_num_elements %zu, controllen %zu, flags %i\n", 
hdr.msg_namelen, hdr.msg_iovlen, hdr.msg_controllen, hdr.msg_flags);
	printf("***         : iovec's iov_len %zu\n", hdr.msg_iov->iov_len);

	/* iovec contents: 30 0 0 0 (length = 48) 1d 0 (type = 29) 5 0 (flags) 37 f3 83 57 (seqno) 0 0 0 0 (pid) 
         *       	   a (family) 0 0 0 3 (ifindex) 0 0 0 80 (state = PERMANENT) 0 (flags) 0 (type) 0 
         *       	   14 0 (rtattr: length) 1 0 (type: destination IP) [20 1 d b8 0 0 1 0 38 cb 35 b9 73 94 ca 34 = IP] */
	
	if (sendmsg(nl_sock, &hdr, 0) < 0) { // sendmsg(<socket descriptor>, <struct msghdr>, 0)
		printf("ping_common.c | Error sending message to kernel, errno: %i [%s]\n", errno, strerror(errno));
		errno = 0;
	} else
		printf("ping_common.c | Successfully sent message over netlink socket\n");
	
	/* // GIVING UP EVERYTHING AND TRYING TO GET RTM_GETNEIGH working???
	   // Result: operation not permitted
        struct {
                struct nlmsghdr getnlh;
                struct rtgenmsg getg;
        } getreq;

        memset(&getreq, 0, sizeof(getreq));
        getreq.getnlh.nlmsg_len = sizeof(getreq);
        getreq.getnlh.nlmsg_type = RTM_GETNEIGH;
        getreq.getnlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
        getreq.getnlh.nlmsg_pid = 0;
        getreq.getnlh.nlmsg_seq = seqNo;
        getreq.getg.rtgen_family = AF_INET6;

        send(nl_sock, (void*)&getreq, sizeof(getreq), 0); */

	// Wait for and process the ack from kernel
	//========== NOTE: adopted from iproute2:ipneigh's use of libnetlink
	char buf[16384];
	int status;
	struct nlmsghdr *h;
	memset(buf, 0, sizeof(buf));
	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(nl_sock, &hdr, 0);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			perror("OVERRUN");
			continue;
		}
		if (status == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return -1;
		}
		if (hdr.msg_namelen != sizeof(struct sockaddr_nl)) {
			fprintf(stderr, "sender address length == %d\n", hdr.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr *)buf; (unsigned)status >= sizeof(*h); ) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);
			if (l < 0 || len > status) {
				if (hdr.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "Truncated message\n");
					return -1;
				}
				fprintf(stderr, "!!!malformed message: len=%d\n", len);
				exit(1);
			}
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *msgerr = (struct nlmsgerr*)NLMSG_DATA(h);
				if ((unsigned)l < sizeof(struct nlmsgerr))
					fprintf(stderr, "ERROR truncated\n");
				else {
					errno = -msgerr->error;
					if (errno == 0) {
						return 0;
					}
					perror("RTNETLINK answers");
				}
				return -1;
			}
			fprintf(stderr, "Unexpected reply!!!\n");
			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h+ NLMSG_ALIGN(len));
		}
		if (hdr.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
	//========== NOTE: adopted from iproute2:ipneigh's use of libnetlink

	printf("ping_common.c | Exiting ncping_clear_neigh_cache function\n");

	/* free(nlhdr); */
	free(nl_sock_addr);
#endif

	return 0;
}

void limit_capabilities(void)
{
#ifdef CAPABILITIES
	cap_t cap_cur_p;
	cap_t cap_p;
	cap_flag_value_t cap_ok;

	cap_cur_p = cap_get_proc();
	if (!cap_cur_p) {
		perror("ping: cap_get_proc");
		exit(-1);
	}

	cap_p = cap_init();
	if (!cap_p) {
		perror("ping: cap_init");
		exit(-1);
	}

	cap_ok = CAP_CLEAR;
	cap_get_flag(cap_cur_p, CAP_NET_ADMIN, CAP_PERMITTED, &cap_ok);

	if (cap_ok != CAP_CLEAR)
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_admin, CAP_SET);

	cap_ok = CAP_CLEAR;
	cap_get_flag(cap_cur_p, CAP_NET_RAW, CAP_PERMITTED, &cap_ok);

	if (cap_ok != CAP_CLEAR)
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_raw, CAP_SET);

	if (cap_set_proc(cap_p) < 0) {
		perror("ping: cap_set_proc");
		exit(-1);
	}

	if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
		perror("ping: prctl");
		exit(-1);
	}

	if (setuid(getuid()) < 0) {
		perror("setuid");
		exit(-1);
	}

	if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
		perror("ping: prctl");
		exit(-1);
	}

	cap_free(cap_p);
	cap_free(cap_cur_p);
#endif
	uid = getuid();
	euid = geteuid();
#ifndef CAPABILITIES
	if (seteuid(uid)) {
		perror("ping: setuid");
		exit(-1);
	}
#endif
}

#ifdef CAPABILITIES
int modify_capability(cap_value_t cap, cap_flag_value_t on)
{
	cap_t cap_p = cap_get_proc();
	cap_flag_value_t cap_ok;
	int rc = -1;

	if (!cap_p) {
		perror("ping: cap_get_proc");
		goto out;
	}

	cap_ok = CAP_CLEAR;
	cap_get_flag(cap_p, cap, CAP_PERMITTED, &cap_ok);
	if (cap_ok == CAP_CLEAR) {
		rc = on ? -1 : 0;
		goto out;
	}

	cap_set_flag(cap_p, CAP_EFFECTIVE, 1, &cap, on);

	if (cap_set_proc(cap_p) < 0) {
		perror("ping: cap_set_proc");
		goto out;
	}

	cap_free(cap_p);

	rc = 0;
out:
	if (cap_p)
		cap_free(cap_p);
	return rc;
}
#else
int modify_capability(int on)
{
	if (seteuid(on ? euid : getuid())) {
		perror("seteuid");
		return -1;
	}

	return 0;
}
#endif

void drop_capabilities(void)
{
#ifdef CAPABILITIES
	cap_t cap = cap_init();
	if (cap_set_proc(cap) < 0) {
		perror("ping: cap_set_proc");
		exit(-1);
	}
	cap_free(cap);
#else
	if (setuid(getuid())) {
		perror("ping: setuid");
		exit(-1);
	}
#endif
}

/* Fills all the outpack, excluding ICMP header, but _including_
 * timestamp area with supplied pattern.
 */
static void fill(char *patp)
{
	int ii, jj, kk;
	int pat[16];
	char *cp;
	u_char *bp = outpack+8;

#ifdef USE_IDN
	setlocale(LC_ALL, "C");
#endif

	for (cp = patp; *cp; cp++) {
		if (!isxdigit(*cp)) {
			fprintf(stderr,
				"ping: patterns must be specified as hex digits.\n");
			exit(2);
		}
	}
	ii = sscanf(patp,
	    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
	    &pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
	    &pat[13], &pat[14], &pat[15]);

	if (ii > 0) {
		for (kk = 0; kk <= maxpacket - (8 + ii); kk += ii)
			for (jj = 0; jj < ii; ++jj)
				bp[jj + kk] = pat[jj];
	}
	if (!(options & F_QUIET)) {
		printf("PATTERN: 0x");
		for (jj = 0; jj < ii; ++jj)
			printf("%02x", bp[jj] & 0xFF);
		printf("\n");
	}

#ifdef USE_IDN
	setlocale(LC_ALL, "");
#endif
}

void common_options(int ch)
{
	switch(ch) {
	case 'a':
		options |= F_AUDIBLE;
		break;
	case 'A':
		options |= F_ADAPTIVE;
		break;
	case 'c':
		npackets = atoi(optarg);
		if (npackets <= 0) {
			fprintf(stderr, "ping: bad number of packets to transmit.\n");
			exit(2);
		}
		break;
	case 'd':
		options |= F_SO_DEBUG;
		break;
	case 'D':
		options |= F_PTIMEOFDAY;
		break;
	case 'i':		/* wait between sending packets */
	{
		double dbl;
		char *ep;

		errno = 0;
		dbl = strtod(optarg, &ep);

		if (errno || *ep != '\0' ||
		    !finite(dbl) || dbl < 0.0 || dbl >= (double)INT_MAX / 1000 - 1.0) {
			fprintf(stderr, "ping: bad timing interval\n");
			exit(2);
		}

		interval = (int)(dbl * 1000);

		options |= F_INTERVAL;
		break;
	}
	case 'm':
	{
		char *endp;
		mark = (int)strtoul(optarg, &endp, 10);
		if (mark < 0 || *endp != '\0') {
			fprintf(stderr, "mark cannot be negative\n");
			exit(2);
		}
		options |= F_MARK;
		break;
	}
	case 'w':
		deadline = atoi(optarg);
		if (deadline < 0) {
			fprintf(stderr, "ping: bad wait time.\n");
			exit(2);
		}
		break;
	case 'l':
		preload = atoi(optarg);
		if (preload <= 0) {
			fprintf(stderr, "ping: bad preload value, should be 1..%d\n", MAX_DUP_CHK);
			exit(2);
		}
		if (preload > MAX_DUP_CHK)
			preload = MAX_DUP_CHK;
		if (uid && preload > 3) {
			fprintf(stderr, "ping: cannot set preload to value > 3\n");
			exit(2);
		}
		break;
	case 'O':
		options |= F_OUTSTANDING;
		break;
	case 'S':
		sndbuf = atoi(optarg);
		if (sndbuf <= 0) {
			fprintf(stderr, "ping: bad sndbuf value.\n");
			exit(2);
		}
		break;
	case 'f':
		options |= F_FLOOD;
		setbuf(stdout, (char *)NULL);
		/* fallthrough to numeric - avoid gethostbyaddr during flood */
	case 'n':
		options |= F_NUMERIC;
		break;
	case 'p':		/* fill buffer with user pattern */
		options |= F_PINGFILLED;
		fill(optarg);
		break;
	case 'q':
		options |= F_QUIET;
		break;
	case 'r':
		options |= F_SO_DONTROUTE;
		break;
	case 's':		/* size of packet to send */
		datalen = atoi(optarg);
		if (datalen < 0) {
			fprintf(stderr, "ping: illegal negative packet size %d.\n", datalen);
			exit(2);
		}
		if (datalen > maxpacket - 8) {
			fprintf(stderr, "ping: packet size too large: %d\n",
				datalen);
			exit(2);
		}
		break;
	case 'v':
		options |= F_VERBOSE;
		break;
	case 'L':
		options |= F_NOLOOP;
		break;
	case 't':
		options |= F_TTL;
		ttl = atoi(optarg);
		if (ttl < 0 || ttl > 255) {
			fprintf(stderr, "ping: ttl %u out of range\n", ttl);
			exit(2);
		}
		break;
	case 'U':
		options |= F_LATENCY;
		break;
	case 'B':
		options |= F_STRICTSOURCE;
		break;
	case 'W':
		lingertime = atoi(optarg);
		if (lingertime < 0 || lingertime > INT_MAX/1000000) {
			fprintf(stderr, "ping: bad linger time.\n");
			exit(2);
		}
		lingertime *= 1000;
		break;
	case 'V':
		printf("ping utility, iputils-%s\n", SNAPSHOT);
		exit(0);
	default:
		abort();
	}
}


static void sigexit(int signo)
{
	exiting = 1;
	if (in_pr_addr)
		longjmp(pr_addr_jmp, 0);
}

static void sigstatus(int signo)
{
	status_snapshot = 1;
}


int __schedule_exit(int next)
{
	static unsigned long waittime;
	struct itimerval it;

	if (waittime)
		return next;

	if (nreceived) {
		waittime = 2 * tmax;
		if (waittime < 1000*interval)
			waittime = 1000*interval;
	} else
		waittime = lingertime*1000;

	if (next < 0 || next < waittime/1000)
		next = waittime/1000;

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_usec = 0;
	it.it_value.tv_sec = waittime/1000000;
	it.it_value.tv_usec = waittime%1000000;
	setitimer(ITIMER_REAL, &it, NULL);
	return next;
}

static inline void update_interval(void)
{
	int est = rtt ? rtt/8 : interval*1000;

	interval = (est+rtt_addend+500)/1000;
	if (uid && interval < MINUSERINTERVAL)
		interval = MINUSERINTERVAL;
}

/*
 * Print timestamp
 */
void print_timestamp(void)
{
	if (options & F_PTIMEOFDAY) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		printf("[%lu.%06lu] ",
		       (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
	}
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int pinger(void)
{
	static int oom_count;
	static int tokens;
	int i;

	/* Have we already sent enough? If we have, return an arbitrary positive value. */
	if (exiting || (npackets && ntransmitted >= npackets && !deadline))
		return 1000;

	/* Check that packets < rate*time + preload */
	if (cur_time.tv_sec == 0) {
		gettimeofday(&cur_time, NULL);
		tokens = interval*(preload-1);
	} else {
		long ntokens;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ntokens = (tv.tv_sec - cur_time.tv_sec)*1000 +
			(tv.tv_usec-cur_time.tv_usec)/1000;
		if (!interval) {
			/* Case of unlimited flood is special;
			 * if we see no reply, they are limited to 100pps */
			if (ntokens < MININTERVAL && in_flight() >= preload)
				return MININTERVAL-ntokens;
		}
		ntokens += tokens;
		if (ntokens > interval*preload)
			ntokens = interval*preload;
		if (ntokens < interval)
			return interval - ntokens;

		cur_time = tv;
		tokens = ntokens - interval;
	}

	if (options & F_OUTSTANDING) {
		if (ntransmitted > 0 && !rcvd_test(ntransmitted)) {
			print_timestamp();
			printf("no answer yet for icmp_seq=%lu\n", (ntransmitted % MAX_DUP_CHK));
			fflush(stdout);
		}
	}

resend:
	i = send_probe();

	if (i == 0) {
		oom_count = 0;
		advance_ntransmitted();
		if (!(options & F_QUIET) && (options & F_FLOOD)) {
			/* Very silly, but without this output with
			 * high preload or pipe size is very confusing. */
			if ((preload < screen_width && pipesize < screen_width) ||
			    in_flight() < screen_width)
				write_stdout(".", 1);
		}
		return interval - tokens;
	}

	/* And handle various errors... */
	if (i > 0) {
		/* Apparently, it is some fatal bug. */
		abort();
	} else if (errno == ENOBUFS || errno == ENOMEM) {
		int nores_interval;

		/* Device queue overflow or OOM. Packet is not sent. */
		tokens = 0;
		/* Slowdown. This works only in adaptive mode (option -A) */
		rtt_addend += (rtt < 8*50000 ? rtt/8 : 50000);
		if (options&F_ADAPTIVE)
			update_interval();
		nores_interval = SCHINT(interval/2);
		if (nores_interval > 500)
			nores_interval = 500;
		oom_count++;
		if (oom_count*nores_interval < lingertime)
			return nores_interval;
		i = 0;
		/* Fall to hard error. It is to avoid complete deadlock
		 * on stuck output device even when dealine was not requested.
		 * Expected timings are screwed up in any case, but we will
		 * exit some day. :-) */
	} else if (errno == EAGAIN) {
		/* Socket buffer is full. */
		tokens += interval;
		return MININTERVAL;
	} else {
		if ((i=receive_error_msg()) > 0) {
			/* An ICMP error arrived. */
			tokens += interval;
			return MININTERVAL;
		}
		/* Compatibility with old linuces. */
		if (i == 0 && confirm_flag && errno == EINVAL) {
			confirm_flag = 0;
			errno = 0;
		}
		if (!errno)
			goto resend;
	}

	/* Hard local error. Pretend we sent packet. */
	advance_ntransmitted();

	if (i == 0 && !(options & F_QUIET)) {
		if (options & F_FLOOD)
			write_stdout("E", 1);
		else
			perror("ping: sendmsg");
	}
	tokens = 0;
	return SCHINT(interval);
}

/* Set socket buffers, "alloc" is an estimate of memory taken by single packet. */

void sock_setbufs(int icmp_sock, int alloc)
{
	int rcvbuf, hold;
	socklen_t tmplen = sizeof(hold);

	if (!sndbuf)
		sndbuf = alloc;
	setsockopt(icmp_sock, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));

	rcvbuf = hold = alloc * preload;
	if (hold < 65536)
		hold = 65536;
	setsockopt(icmp_sock, SOL_SOCKET, SO_RCVBUF, (char *)&hold, sizeof(hold));
	if (getsockopt(icmp_sock, SOL_SOCKET, SO_RCVBUF, (char *)&hold, &tmplen) == 0) {
		if (hold < rcvbuf)
			fprintf(stderr, "WARNING: probably, rcvbuf is not enough to hold preload.\n");
	}
}

/* Protocol independent setup and parameter checks. */

void setup(int icmp_sock)
{
	int hold;
	struct timeval tv;
	sigset_t sset;

	if ((options & F_FLOOD) && !(options & F_INTERVAL))
		interval = 0;

	if (uid && interval < MINUSERINTERVAL) {
		fprintf(stderr, "ping: cannot flood; minimal interval, allowed for user, is %dms\n", MINUSERINTERVAL);
		exit(2);
	}

	if (interval >= INT_MAX/preload) {
		fprintf(stderr, "ping: illegal preload and/or interval\n");
		exit(2);
	}

	hold = 1;
	if (options & F_SO_DEBUG)
		setsockopt(icmp_sock, SOL_SOCKET, SO_DEBUG, (char *)&hold, sizeof(hold));
	if (options & F_SO_DONTROUTE)
		setsockopt(icmp_sock, SOL_SOCKET, SO_DONTROUTE, (char *)&hold, sizeof(hold));

#ifdef SO_TIMESTAMP
	if (!(options&F_LATENCY)) {
		int on = 1;
		if (setsockopt(icmp_sock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)))
			fprintf(stderr, "Warning: no SO_TIMESTAMP support, falling back to SIOCGSTAMP\n");
	}
#endif
#ifdef SO_MARK
	if (options & F_MARK) {
		int ret;

		enable_capability_admin();
		ret = setsockopt(icmp_sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
		disable_capability_admin();

		if (ret == -1) {
			/* we probably dont wanna exit since old kernels
			 * dont support mark ..
			*/
			fprintf(stderr, "Warning: Failed to set mark %d\n", mark);
		}
	}
#endif

	/* Set some SNDTIMEO to prevent blocking forever
	 * on sends, when device is too slow or stalls. Just put limit
	 * of one second, or "interval", if it is less.
	 */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if (interval < 1000) {
		tv.tv_sec = 0;
		tv.tv_usec = 1000 * SCHINT(interval);
	}
	setsockopt(icmp_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

	/* Set RCVTIMEO to "interval". Note, it is just an optimization
	 * allowing to avoid redundant poll(). */
	tv.tv_sec = SCHINT(interval)/1000;
	tv.tv_usec = 1000*(SCHINT(interval)%1000);
	if (setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)))
		options |= F_FLOOD_POLL;

	if (!(options & F_PINGFILLED)) {
		int i;
		u_char *p = outpack+8;

		/* Do not forget about case of small datalen,
		 * fill timestamp area too!
		 */
		for (i = 0; i < datalen; ++i)
			*p++ = i;
	}

	ident = htons(getpid() & 0xFFFF);

	set_signal(SIGINT, sigexit);
	set_signal(SIGALRM, sigexit);
	set_signal(SIGQUIT, sigstatus);

	sigemptyset(&sset);
	sigprocmask(SIG_SETMASK, &sset, NULL);

	gettimeofday(&start_time, NULL);

	if (deadline) {
		struct itimerval it;

		it.it_interval.tv_sec = 0;
		it.it_interval.tv_usec = 0;
		it.it_value.tv_sec = deadline;
		it.it_value.tv_usec = 0;
		setitimer(ITIMER_REAL, &it, NULL);
	}

	if (isatty(STDOUT_FILENO)) {
		struct winsize w;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
			if (w.ws_col > 0)
				screen_width = w.ws_col;
		}
	}
}

/* daveti: extended for arpsec */
void main_loop(int icmp_sock, __u8 *packet, int packlen, int nl_sock, int ncping, char *tip)
{
	char addrbuf[128];
	char ans_data[4096];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *c;
	int cc;
	int next;
	int polling;

	/* daveti: debug */
	int dd = 0;

	iov.iov_base = (char *)packet;

	for (;;) {
		/* Check exit conditions. */
		if (exiting)
			break;
		if (npackets && nreceived + nerrors >= npackets)
			break;
		if (deadline && nerrors)
			break;
		/* Check for and do special actions. */
		if (status_snapshot)
			status();

		/* Send probes scheduled to this time. */
		do {
			/* daveti: arpsec ncping */
			if (ncping) {
				dd++;
				sleep(NCPING_ARPSEC_SLEEP_TIME);

				/* printf("----- Print out neighbor cache\n");
				if (system("ip -6 neigh") < 0)
					printf("Failed to print neighbor cache\n");
				printf("----- End printing neighbor cache\n"); */

#ifndef CLEARWITHOUTSYS
				/* jochoi: Backup Plan */
				/* jochoi: NOTE cache is cleared before each ping operation, but
				 *         cache is not cleared after last ping (ip neigh will show REACHABLE) */
				if (system(DELETE_NEIGH_CMD) < 0)
				 	printf("main loop: Failed to delete the neighbor cache entry\n");
#else
				next = ncping_clear_neigh_cache(nl_sock, tip);
				if (next != 0)
					printf("Error: ncping6 unable to clear the neigh cache for IP [%s]\n",
						tip);
				printf("daveti: debug [%d]\n", dd);
#endif
			}

			next = pinger();
			next = schedule_exit(next);
		} while (next <= 0);

		/* "next" is time to send next probe, if positive.
		 * If next<=0 send now or as soon as possible. */

		/* Technical part. Looks wicked. Could be dropped,
		 * if everyone used the newest kernel. :-)
		 * Its purpose is:
		 * 1. Provide intervals less than resolution of scheduler.
		 *    Solution: spinning.
		 * 2. Avoid use of poll(), when recvmsg() can provide
		 *    timed waiting (SO_RCVTIMEO). */
		polling = 0;
		if ((options & (F_ADAPTIVE|F_FLOOD_POLL)) || next<SCHINT(interval)) {
			int recv_expected = in_flight();

			/* If we are here, recvmsg() is unable to wait for
			 * required timeout. */
			if (1000 % HZ == 0 ? next <= 1000 / HZ : (next < INT_MAX / HZ && next * HZ <= 1000)) {
				/* Very short timeout... So, if we wait for
				 * something, we sleep for MININTERVAL.
				 * Otherwise, spin! */
				if (recv_expected) {
					next = MININTERVAL;
				} else {
					next = 0;
					/* When spinning, no reasons to poll.
					 * Use nonblocking recvmsg() instead. */
					polling = MSG_DONTWAIT;
					/* But yield yet. */
					sched_yield();
				}
			}

			if (!polling &&
			    ((options & (F_ADAPTIVE|F_FLOOD_POLL)) || interval)) {
				struct pollfd pset;
				pset.fd = icmp_sock;
				pset.events = POLLIN|POLLERR;
				pset.revents = 0;
				if (poll(&pset, 1, next) < 1 ||
				    !(pset.revents&(POLLIN|POLLERR)))
					continue;
				polling = MSG_DONTWAIT;
			}
		}

		for (;;) {
			struct timeval *recv_timep = NULL;
			struct timeval recv_time;
			int not_ours = 0; /* Raw socket can receive messages
					   * destined to other running pings. */

			iov.iov_len = packlen;
			memset(&msg, 0, sizeof(msg));
			msg.msg_name = addrbuf;
			msg.msg_namelen = sizeof(addrbuf);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = ans_data;
			msg.msg_controllen = sizeof(ans_data);

			cc = recvmsg(icmp_sock, &msg, polling);
			polling = MSG_DONTWAIT;

			if (cc < 0) {
				if (errno == EAGAIN || errno == EINTR)
					break;
				if (!receive_error_msg()) {
					if (errno) {
						perror("ping: recvmsg");
						break;
					}
					not_ours = 1;
				}
			} else {

#ifdef SO_TIMESTAMP
				for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
					if (c->cmsg_level != SOL_SOCKET ||
					    c->cmsg_type != SO_TIMESTAMP)
						continue;
					if (c->cmsg_len < CMSG_LEN(sizeof(struct timeval)))
						continue;
					recv_timep = (struct timeval*)CMSG_DATA(c);
				}
#endif

				if ((options&F_LATENCY) || recv_timep == NULL) {
					if ((options&F_LATENCY) ||
					    ioctl(icmp_sock, SIOCGSTAMP, &recv_time))
						gettimeofday(&recv_time, NULL);
					recv_timep = &recv_time;
				}

				not_ours = parse_reply(&msg, cc, addrbuf, recv_timep);
			}

			/* See? ... someone runs another ping on this host. */
			if (not_ours)
				install_filter();

			/* If nothing is in flight, "break" returns us to pinger. */
			if (in_flight() == 0)
				break;

			/* Otherwise, try to recvmsg() again. recvmsg()
			 * is nonblocking after the first iteration, so that
			 * if nothing is queued, it will receive EAGAIN
			 * and return to pinger. */
		}
	}
	drop_capabilities(); // jochoi
	finish();
}

int gather_statistics(__u8 *icmph, int icmplen,
		      int cc, __u16 seq, int hops,
		      int csfailed, struct timeval *tv, char *from,
		      void (*pr_reply)(__u8 *icmph, int cc))
{
	int dupflag = 0;
	long triptime = 0;
	__u8 *ptr = icmph + icmplen;

	++nreceived;
	if (!csfailed)
		acknowledge(seq);

	if (timing && cc >= 8+sizeof(struct timeval)) {
		struct timeval tmp_tv;
		memcpy(&tmp_tv, ptr, sizeof(tmp_tv));

restamp:
		tvsub(tv, &tmp_tv);
		triptime = tv->tv_sec * 1000000 + tv->tv_usec;
		if (triptime < 0) {
			fprintf(stderr, "Warning: time of day goes back (%ldus), taking countermeasures.\n", triptime);
			triptime = 0;
			if (!(options & F_LATENCY)) {
				gettimeofday(tv, NULL);
				options |= F_LATENCY;
				goto restamp;
			}
		}
		if (!csfailed) {
			/* daveti: arpsec ncping */
			if (triptime >= NCPING_ARPSEC_RTT_THRESHOLD) {
				--nreceived;
				++nreceived_arpsec;

				tsum_arpsec += triptime;
				tsum2_arpsec += (long long)triptime * (long long)triptime;
				if (triptime < tmin_arpsec)
					tmin_arpsec = triptime;
				if (triptime > tmax_arpsec)
				tmax_arpsec = triptime;
			} else {
				tsum += triptime;
				tsum2 += (long long)triptime * (long long)triptime;
				if (triptime < tmin)
					tmin = triptime;
				if (triptime > tmax)
					tmax = triptime;
			}
			if (!rtt)
				rtt = triptime*8;
			else
				rtt += triptime-rtt/8;
			if (options&F_ADAPTIVE)
				update_interval();
		}
	}

	if (csfailed) {
		++nchecksum;
		--nreceived;
	} else if (rcvd_test(seq)) {
		++nrepeats;
		--nreceived;
		dupflag = 1;
	} else {
		rcvd_set(seq);
		dupflag = 0;
	}
	confirm = confirm_flag;

	if (options & F_QUIET)
		return 1;

	if (options & F_FLOOD) {
		if (!csfailed)
			write_stdout("\b \b", 3);
		else
			write_stdout("\bC", 2);
	} else {
		int i;
		__u8 *cp, *dp;

		print_timestamp();
		printf("%d bytes from %s:", cc, from);

		if (pr_reply)
			pr_reply(icmph, cc);

		if (hops >= 0)
			printf(" ttl=%d", hops);

		if (cc < datalen+8) {
			printf(" (truncated)\n");
			return 1;
		}
		if (timing) {
			if (triptime >= 100000)
				printf(" time=%ld ms", triptime/1000);
			else if (triptime >= 10000)
				printf(" time=%ld.%01ld ms", triptime/1000,
				       (triptime%1000)/100);
			else if (triptime >= 1000)
				printf(" time=%ld.%02ld ms", triptime/1000,
				       (triptime%1000)/10);
			else
				printf(" time=%ld.%03ld ms", triptime/1000,
				       triptime%1000);
		}
		if (dupflag)
			printf(" (DUP!)");
		if (csfailed)
			printf(" (BAD CHECKSUM!)");

		/* check the data */
		cp = ((u_char*)ptr) + sizeof(struct timeval);
		dp = &outpack[8 + sizeof(struct timeval)];
		for (i = sizeof(struct timeval); i < datalen; ++i, ++cp, ++dp) {
			if (*cp != *dp) {
				printf("\nwrong data byte #%d should be 0x%x but was 0x%x",
				       i, *dp, *cp);
				cp = (u_char*)ptr + sizeof(struct timeval);
				for (i = sizeof(struct timeval); i < datalen; ++i, ++cp) {
					if ((i % 32) == sizeof(struct timeval))
						printf("\n#%d\t", i);
					printf("%x ", *cp);
				}
				break;
			}
		}
	}
	return 0;
}

static long llsqrt(long long a)
{
	long long prev = ~((long long)1 << 63);
	long long x = a;

	if (x > 0) {
		while (x < prev) {
			prev = x;
			x = (x+(a/x))/2;
		}
	}

	return (long)x;
}

/*
 * finish --
 *	Print out statistics, and give up.
 */
void finish(void)
{
	struct timeval tv = cur_time;
	char *comma = "";

	tvsub(&tv, &start_time);

	putchar('\n');
	fflush(stdout);
	printf("--- %s ping statistics ---\n", hostname);
	printf("%ld packets transmitted, ", ntransmitted);
	printf("%ld received", nreceived);
	if (nrepeats)
		printf(", +%ld duplicates", nrepeats);
	if (nchecksum)
		printf(", +%ld corrupted", nchecksum);
	if (nerrors)
		printf(", +%ld errors", nerrors);
	if (ntransmitted) {
		printf(", %d%% packet loss",
		       (int) ((((long long)(ntransmitted - nreceived)) * 100) /
			      ntransmitted));
		printf(", time %ldms", 1000*tv.tv_sec+tv.tv_usec/1000);
	}

	/* daveti: ncping */
	if (nreceived_arpsec)
		printf(", +%ld received(thresholded)", nreceived_arpsec);
	if (nrepeats_arpsec)
		printf(", +%ld duplicates(thresholded)", nrepeats_arpsec);

	putchar('\n');

	if (nreceived && timing) {
		long tmdev;

		tsum /= nreceived + nrepeats;
		tsum2 /= nreceived + nrepeats;
		tmdev = llsqrt(tsum2 - tsum * tsum);

		printf("rtt min/avg/max/mdev = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld ms",
		       (long)tmin/1000, (long)tmin%1000,
		       (unsigned long)(tsum/1000), (long)(tsum%1000),
		       (long)tmax/1000, (long)tmax%1000,
		       (long)tmdev/1000, (long)tmdev%1000
		       );

		/* daveti: ncping */
		if (nreceived_arpsec + nrepeats_arpsec != 0) {
			long tmdev_arpsec;
			tsum_arpsec /= nreceived_arpsec + nrepeats_arpsec;
			tsum2_arpsec /= nreceived_arpsec + nrepeats_arpsec;
			tmdev_arpsec = llsqrt(tsum2_arpsec - tsum_arpsec * tsum_arpsec);

                	printf("rtt(thresholded) min/avg/max/mdev = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld ms\n",
				(long)tmin_arpsec/1000, (long)tmin_arpsec%1000,
				(unsigned long)(tsum_arpsec/1000), (long)(tsum_arpsec%1000),
				(long)tmax_arpsec/1000, (long)tmax_arpsec%1000,
				(long)tmdev_arpsec/1000, (long)tmdev_arpsec%1000
				);
		} else {
			printf("No arpsec thresholded rtt value");
		}

		comma = ", ";
	}
	if (pipesize > 1) {
		printf("%spipe %d", comma, pipesize);
		comma = ", ";
	}
	if (nreceived && (!interval || (options&(F_FLOOD|F_ADAPTIVE))) && ntransmitted > 1) {
		int ipg = (1000000*(long long)tv.tv_sec+tv.tv_usec)/(ntransmitted-1);
		printf("%sipg/ewma %d.%03d/%d.%03d ms",
		       comma, ipg/1000, ipg%1000, rtt/8000, (rtt/8)%1000);
	}
	putchar('\n');
	exit(!nreceived || (deadline && nreceived < npackets));
}


void status(void)
{
	int loss = 0;
	long tavg = 0;

	status_snapshot = 0;

	if (ntransmitted)
		loss = (((long long)(ntransmitted - nreceived)) * 100) / ntransmitted;

	fprintf(stderr, "\r%ld/%ld packets, %d%% loss", ntransmitted, nreceived, loss);

	if (nreceived && timing) {
		tavg = tsum / (nreceived + nrepeats);

		fprintf(stderr, ", min/avg/ewma/max = %ld.%03ld/%lu.%03ld/%d.%03d/%ld.%03ld ms",
		       (long)tmin/1000, (long)tmin%1000,
		       tavg/1000, tavg%1000,
		       rtt/8000, (rtt/8)%1000,
		       (long)tmax/1000, (long)tmax%1000
		       );
	}
	fprintf(stderr, "\n");
}

