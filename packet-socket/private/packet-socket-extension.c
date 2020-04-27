#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h> /* for htons */

#include <signal.h>
#include <poll.h>

#if defined(__linux__)
#include <net/if_arp.h>
#include <netpacket/packet.h>
#endif

#if defined(__APPLE__)
#include <net/if_dl.h>
#include <net/bpf.h>
#endif

#define PREFIX(id) packet_socket_ ## id

/***************************************************************************/
/* Linux-specific implementation */

#if defined(__linux__)

static int lookupInterfaceInfo(int sock, char const *interfaceName, int info, struct ifreq *ifr) {
  strncpy(ifr->ifr_name, interfaceName, IFNAMSIZ);
  if (ioctl(sock, info, ifr) < 0) {
    perror("ioctl error while looking performing ioctl on interface");
    fprintf(stderr, "(ioctl number 0x%08x, interface %s)\n", info, interfaceName);
    return -1;
  } else {
    return 0;
  }
}

static int bindToInterface(int sock, char const *interfaceName) {
  struct ifreq ifr;
  struct sockaddr_ll socketAddress;

  if (lookupInterfaceInfo(sock, interfaceName, SIOCGIFINDEX, &ifr) < 0) {
    return -1;
  }

  socketAddress.sll_family = AF_PACKET;
  socketAddress.sll_protocol = htons(ETH_P_ALL);
  socketAddress.sll_ifindex = ifr.ifr_ifindex;

  if (bind(sock, (struct sockaddr *) &socketAddress, sizeof(socketAddress)) < 0) {
    perror("Bind error");
    return -1;
  }

  return 0;
}

static int openSocket(char const *interfaceName) {
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    perror("Socket error");
    return -1;
  }

  if (bindToInterface(sock, interfaceName) == -1) {
    return -1;
  }

  return sock;
}

long PREFIX(read_buffer_length)(int sock) {
  /* If we supply ETHER_MAX_LEN here, then we miss out on the occasional larger (!) packet. */
  /* Instead, we supply something definitely large enough. */
  /* TODO: Consider returning something closer to around 9000 bytes,
     or whatever jumbo packet sizes are these days. */
  return 65536;
}

int PREFIX(extract_packet)(unsigned char const *bufbase, size_t limit, int o, int *basep, int *lenp) {
  *basep = 0;
  *lenp = (o == 0) ? limit : 0;
  return limit;
}

int PREFIX(hwaddr)(int sock, char const *interfaceName, unsigned char *buf, ssize_t *buflen) {
  struct ifreq ifr;
  if (lookupInterfaceInfo(sock, interfaceName, SIOCGIFHWADDR, &ifr) < 0) {
    return -1;
  }

  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    return -1;
  }

  if (*buflen < ETH_ALEN) {
    *buflen = ETH_ALEN;
    return -2;
  } else {
    *buflen = ETH_ALEN;
    memcpy(buf, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
  }
}

/*
static int setPromiscuousMode(int sock, int index) {
  struct packet_mreq req;

  req.mr_ifindex = index;
  req.mr_type = PACKET_MR_PROMISC;

  if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &req, (socklen_t) sizeof(req)) < 0) {
    perror("set sock opt error");
    return -1;
  }

  return 0;
}
*/

#endif

/***************************************************************************/
/* OSX-specific implementation */
#if defined(__APPLE__)

static int openSocket(char const *interfaceName) {
  int deviceIndex;

  for (deviceIndex = 0; deviceIndex < 10; deviceIndex++) {
    int fd = -1;

    {
      char deviceName[32];
      snprintf(deviceName, sizeof(deviceName), "/dev/bpf%d", deviceIndex);
      fd = open(deviceName, O_RDWR);
      if (fd == -1) {
	if (errno != ENOENT) {
	  perror("open /dev/bpfX");
	}
	continue;
      }
    }

    {
      struct ifreq ifr;
      strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ);
      if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
	perror("ioctl BIOCSETIF");
	close(fd);
	continue;
      }
    }

    /* { */
    /*   u_int enable = 1; */
    /*   if (ioctl(fd, BIOCSHDRCMPLT, &enable) < 0) { */
    /* 	perror("ioctl BIOCSHDRCMPLT"); */
    /* 	close(fd); */
    /* 	continue; */
    /*   } */
    /* } */

    /* { */
    /*   u_int enable = 1; */
    /*   if (ioctl(fd, BIOCSSEESENT, &enable) < 0) { */
    /* 	perror("ioctl BIOCSSEESENT"); */
    /* 	close(fd); */
    /* 	continue; */
    /*   } */
    /* } */

    {
      u_int enable = 1;
      if (ioctl(fd, BIOCIMMEDIATE, &enable) < 0) {
	perror("ioctl BIOCIMMEDIATE");
	close(fd);
	continue;
      }
    }

    return fd;
  }

  return -1;
}

long PREFIX(read_buffer_length)(int fd) {
  u_int buflen;
  if (ioctl(fd, BIOCGBLEN, &buflen) < 0) {
    perror("ioctl BIOCGBLEN");
    return -1;
  }
  return buflen;
}

int PREFIX(extract_packet)(unsigned char const *bufbase, size_t limit, int o, int *basep, int *lenp) {
  struct bpf_hdr *bh = (struct bpf_hdr *) (bufbase + o);
  struct ether_header *eh = (struct ether_header *) (bufbase + o + bh->bh_hdrlen);
  int nexto;
  *basep = o + bh->bh_hdrlen;
  *lenp = bh->bh_caplen;
  if (bh->bh_caplen != bh->bh_datalen) {
    fprintf(stderr, "packet-socket: Warning: packet truncated from %u to %u bytes\n",
	    bh->bh_datalen,
	    bh->bh_caplen);
  }
  nexto = o + BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
  /* printf("base %p limit %u o %d *basep now %d *lenp now %d nexto %d\n", */
  /* 	 bufbase, limit, o, *basep, *lenp, nexto); */
  return nexto;
}

int PREFIX(hwaddr)(int sock, char const *interfaceName, unsigned char *buf, ssize_t *buflen) {
  int result = -1;
  struct ifaddrs *addrs;
  struct ifaddrs *tmp;

  if (getifaddrs(&addrs) == -1) {
    perror("getifaddrs");
    return -1;
  }

  for (tmp = addrs; tmp != NULL; tmp = tmp->ifa_next) {
    if (tmp->ifa_addr != NULL &&
	!strncmp(tmp->ifa_name, interfaceName, IFNAMSIZ) &&
	tmp->ifa_addr->sa_family == AF_LINK)
      {
	struct sockaddr_dl *sdl = (struct sockaddr_dl *) tmp->ifa_addr;
        if (*buflen < sdl->sdl_alen) {
          result = -2;
        } else {
          memcpy(buf, LLADDR(sdl), sdl->sdl_alen);
          result = 0;
        }
        *buflen = sdl->sdl_alen;
	break;
      }
  }

  freeifaddrs(addrs);
  return result;
}

#endif

/***************************************************************************/
/* Common implementation */

int PREFIX(enumerate_interfaces)(void (*callback)(char const *name)) {
  struct ifaddrs *addrs;
  struct ifaddrs *tmp;

  if (getifaddrs(&addrs) == -1) {
    perror("getifaddrs");
    return -1;
  }

  for (tmp = addrs; tmp != NULL; tmp = tmp->ifa_next) {
    if (tmp->ifa_addr != NULL) {
      callback(tmp->ifa_name);
    }
  }

  freeifaddrs(addrs);
  return 0;
}

int PREFIX(create_and_bind)(char const *interfaceName) {
  int sock = openSocket(interfaceName);
  if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) return -1;
  return sock;
}

int PREFIX(close)(int sock) {
  if (close(sock) < 0) {
    perror("close");
    return -1;
  }

  return 0;
}

long PREFIX(read)(int sock, unsigned char *read_buffer, long buffer_length, int *truncated) {
  ssize_t bytes_read;

  *truncated = 0;

  while (1) {
#if defined(__APPLE__)
    bytes_read = read(sock, read_buffer, buffer_length);
#else
    bytes_read = recv(sock, read_buffer, buffer_length, MSG_TRUNC);
    if (bytes_read > buffer_length) {
      fprintf(stderr,
              "WARNING: packet-socket buffer size %d too small for received packet of %d bytes\n",
              buffer_length,
              bytes_read);
      *truncated = 1;
      bytes_read = buffer_length;
    }
#endif

    if (bytes_read != -1) break;

    switch (errno) {
      case EINTR: continue;
      case EAGAIN: return -2;
      default: return -1;
    }
  }

  return (long) bytes_read;
}
