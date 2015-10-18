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

#include <pthread.h>

#if defined(__linux__)
#include <net/if_arp.h>
#include <netpacket/packet.h>
#endif

#if defined(__APPLE__)
#include <net/if_dl.h>
#include <net/bpf.h>
#endif

#include "escheme.h"

/***************************************************************************/
/* Linux-specific implementation */

#if defined(__linux__)

static int lookupInterfaceInfo(int sock, char const *interfaceName, int info, struct ifreq *ifr)
  XFORM_SKIP_PROC
{
  strncpy(ifr->ifr_name, interfaceName, IFNAMSIZ);
  if (ioctl(sock, info, ifr) < 0) {
    perror("ioctl error while looking performing ioctl on interface");
    fprintf(stderr, "(ioctl number 0x%08x, interface %s)\n", info, interfaceName);
    return -1;
  } else {
    return 0;
  }
}

static int bindToInterface(int sock, char const *interfaceName)
  XFORM_SKIP_PROC
{
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

static int openSocket(char const *interfaceName)
  XFORM_SKIP_PROC
{
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

static int readBufferLength(int sock)
  XFORM_SKIP_PROC
{
  /* If we supply ETHER_MAX_LEN here, then we miss out on the occasional larger (!) packet. */
  /* Instead, we supply something definitely large enough. */
  /* TODO: Consider returning something closer to around 9000 bytes,
     or whatever jumbo packet sizes are these days. */
  return 65536;
}

static int extractPacket(unsigned char const *bufbase, size_t limit, int o, int *basep, int *lenp) {
  *basep = 0;
  *lenp = (o == 0) ? limit : 0;
  return limit;
}

static Scheme_Object *socket_hwaddr(int argc, Scheme_Object **argv) {
  int sock = SCHEME_INT_VAL(argv[0]);
  char const *interfaceName = SCHEME_BYTE_STR_VAL(argv[1]);
  XFORM_CAN_IGNORE struct ifreq ifr;

  if (lookupInterfaceInfo(sock, interfaceName, SIOCGIFHWADDR, &ifr) < 0) {
    return scheme_false;
  }

  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    return scheme_false;
  }

  return scheme_make_sized_byte_string(ifr.ifr_hwaddr.sa_data, ETH_ALEN, 1);
}

/*
static int setPromiscuousMode(int sock, int index)
  XFORM_SKIP_PROC
{
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

static int openSocket(char const *interfaceName)
  XFORM_SKIP_PROC
{
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

static int readBufferLength(int fd)
  XFORM_SKIP_PROC
{
  u_int buflen;
  if (ioctl(fd, BIOCGBLEN, &buflen) < 0) {
    perror("ioctl BIOCGBLEN");
    return -1;
  }
  return buflen;
}

static int extractPacket(unsigned char const *bufbase, size_t limit, int o, int *basep, int *lenp)
  XFORM_SKIP_PROC
{
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

static Scheme_Object *socket_hwaddr(int argc, Scheme_Object **argv) {
  Scheme_Object *result = scheme_false;
  int sock = SCHEME_INT_VAL(argv[0]);
  char const *interfaceName = SCHEME_BYTE_STR_VAL(argv[1]);
  struct ifaddrs *addrs;
  struct ifaddrs *tmp;

  if (getifaddrs(&addrs) == -1) {
    perror("getifaddrs");
    return scheme_false;
  }

  for (tmp = addrs; tmp != NULL; tmp = tmp->ifa_next) {
    if (tmp->ifa_addr != NULL &&
	!strncmp(tmp->ifa_name, interfaceName, IFNAMSIZ) &&
	tmp->ifa_addr->sa_family == AF_LINK)
      {
	struct sockaddr_dl *sdl = (struct sockaddr_dl *) tmp->ifa_addr;
	result = scheme_make_sized_byte_string(LLADDR(sdl), sdl->sdl_alen, 1);
	break;
      }
  }

  freeifaddrs(addrs);
  return result;
}

#endif

/***************************************************************************/
/* Common implementation */

static Scheme_Object *enumerate_interfaces(int argc, Scheme_Object **argv) {
  Scheme_Object *result = scheme_null;
  struct ifaddrs *addrs;
  struct ifaddrs *tmp;

  if (getifaddrs(&addrs) == -1) {
    perror("getifaddrs");
    return scheme_false;
  }

  for (tmp = addrs; tmp != NULL; tmp = tmp->ifa_next) {
    if (tmp->ifa_addr != NULL) {
      result = scheme_make_pair(scheme_make_utf8_string(tmp->ifa_name), result);
    }
  }

  freeifaddrs(addrs);
  return result;
}

static Scheme_Object *create_and_bind_socket(int argc, Scheme_Object **argv) {
  int sock;
  char const *interfaceName = SCHEME_BYTE_STR_VAL(argv[0]);
  sock = openSocket(interfaceName);
  return (sock == -1) ? scheme_false : scheme_make_integer(sock);
}

static Scheme_Object *close_socket(int argc, Scheme_Object **argv) {
  int sock;
  sock = SCHEME_INT_VAL(argv[0]);

  if (close(sock) < 0) {
    perror("close");
    return scheme_false;
  }

  return scheme_true;
}

static Scheme_Object *socket_read_buffer_length(int argc, Scheme_Object **argv) {
  int sock;
  sock = SCHEME_INT_VAL(argv[0]);
  return scheme_make_integer(readBufferLength(sock));
}

struct ReadArgs {
  int sock;
  unsigned char *buf;
  int blen;
  volatile int bytes_read;
};

static void *do_actual_read(void *read_args)
  XFORM_SKIP_PROC
{
  struct ReadArgs *args = (struct ReadArgs *) read_args;
#if defined(__APPLE__)
  ssize_t result = read(args->sock, args->buf, args->blen);
#else
  ssize_t result = recv(args->sock, args->buf, args->blen, MSG_TRUNC);
  if (result > args->blen) {
    fprintf(stderr,
	    "WARNING: packet-socket buffer size %d too small for received packet of %d bytes\n",
	    args->blen,
	    result);
    result = args->blen;
  }
#endif
  if (result == -1) {
    perror("packet-socket read");
  }
  args->bytes_read = result;
  return NULL;
}

static int is_read_done(Scheme_Object *data) {
  struct ReadArgs *read_args = (struct ReadArgs*) data;
  return read_args->bytes_read != 0;
}

static void prepare_for_sleep(Scheme_Object *data, void *fds) {
  struct ReadArgs *read_args = (struct ReadArgs*) data;
  MZ_FD_SET(read_args->sock, MZ_GET_FDSET(fds, 0));
  MZ_FD_SET(read_args->sock, MZ_GET_FDSET(fds, 2));
}

Scheme_Object *socket_read(int argc, Scheme_Object **argv) {
  struct ReadArgs *read_args;
  size_t buffer_length;
  unsigned char *read_buffer;
  pthread_t read_thread;
  Scheme_Object *result = scheme_null;

  read_args = calloc(1, sizeof(*read_args));
  if (read_args == NULL) {
    perror("socket-read calloc read_args");
    return scheme_false;
  }

  buffer_length = SCHEME_BYTE_STRLEN_VAL(argv[1]);
  read_buffer = calloc(1, buffer_length);
  if (read_buffer == NULL) {
    perror("socket-read calloc read_buffer");
    free(read_args);
    return scheme_false;
  }

  read_args->sock = SCHEME_INT_VAL(argv[0]);
  read_args->buf = read_buffer;
  read_args->blen = buffer_length;
  read_args->bytes_read = 0;

  /* fprintf(stderr, "original thread sock: %d, buf: %p, len: %d\n", */
  /* 	  read_args->sock, */
  /* 	  read_args->buf, */
  /* 	  read_args->blen); */

  pthread_create(&read_thread, NULL, do_actual_read, read_args);
  scheme_block_until(is_read_done, prepare_for_sleep, (Scheme_Object *) read_args, 0);

  if (read_args->bytes_read < 0) {
    result = scheme_false;
  } else {
    int extractionState = 0;
    int baseOffset = 0;
    int length = 0;
    Scheme_Object *entry = scheme_null;

    do {
      extractionState = extractPacket(read_args->buf, read_args->bytes_read, extractionState,
				      &baseOffset,
				      &length);
      entry = scheme_make_pair(scheme_make_integer(baseOffset), scheme_make_integer(length));
      result = scheme_make_pair(entry, result);
    } while (extractionState < read_args->bytes_read);

    /* It's a shame this is necessary, but the GC can move the buffer
       unpredictably so we can't read straight into it. TODO: see if
       there's some way of pinning the Racket buffer in order to avoid
       the copy? */
    memcpy(SCHEME_BYTE_STR_VAL(argv[1]), read_buffer, read_args->bytes_read);
  }

  pthread_join(read_thread, NULL);
  free(read_buffer);
  free(read_args);
  return result;
}

static Scheme_Object *socket_write(int argc, Scheme_Object **argv) {
  int sock;
  char *buf;
  int blen, bytes_written;

  sock = SCHEME_INT_VAL(argv[0]);
  buf =  SCHEME_BYTE_STR_VAL(argv[1]);
  blen = SCHEME_BYTE_STRLEN_VAL(argv[1]);
  bytes_written = write(sock, buf, blen);
  return scheme_make_integer(bytes_written);
}

Scheme_Object *scheme_reload(Scheme_Env *env) {
  Scheme_Env *module_env;
  Scheme_Object *proc;

  module_env = scheme_primitive_module(scheme_intern_symbol("packet-socket-extension"), env);

  proc = scheme_make_prim_w_arity(enumerate_interfaces, "enumerate-interfaces", 0, 0);
  scheme_add_global("enumerate-interfaces", proc, module_env);

  proc = scheme_make_prim_w_arity(close_socket, "socket-close", 1, 1);
  scheme_add_global("socket-close", proc, module_env);

  proc = scheme_make_prim_w_arity(create_and_bind_socket, "create-and-bind-socket", 1, 1);
  scheme_add_global("create-and-bind-socket", proc, module_env);

  proc = scheme_make_prim_w_arity(socket_read_buffer_length, "socket-read-buffer-length", 1, 1);
  scheme_add_global("socket-read-buffer-length", proc, module_env);

  proc = scheme_make_prim_w_arity(socket_read, "socket-read", 2, 2);
  scheme_add_global("socket-read", proc, module_env);

  proc = scheme_make_prim_w_arity(socket_write, "socket-write", 2, 2);
  scheme_add_global("socket-write", proc, module_env);

  proc = scheme_make_prim_w_arity(socket_hwaddr, "socket-hwaddr", 2, 2);
  scheme_add_global("socket-hwaddr", proc, module_env);

  scheme_finish_primitive_module(module_env);
  return scheme_void;
}

Scheme_Object *scheme_initialize(Scheme_Env *env) {
  return scheme_reload(env);
}

Scheme_Object *scheme_module_name() {
  return scheme_intern_symbol("packet-socket-extension");
}
