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

#if defined(__linux__)
#include <netpacket/packet.h>
#endif

#if defined(__APPLE__)
#include <net/bpf.h>
#endif

#include "escheme.h"

/***************************************************************************/
/* Linux-specific implementation */

#if defined(__linux__)

static int getInterfaceIndexInternal(int sock, char const *interfaceName)
  XFORM_SKIP_PROC
{
  struct ifreq ifr;
  int index_result;

  strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ);
  /* printf("The interface for index: %s\n", ifr->ifr_name); */

  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl error while looking up interface");
    return -1;
  }

  return ifr.ifr_ifindex;
}

static int bindToInterface(int sock, char const *interfaceName)
  XFORM_SKIP_PROC
{
  struct sockaddr_ll socketAddress;
  socketAddress.sll_family = AF_PACKET;
  socketAddress.sll_protocol = htons(ETH_P_ALL);
  socketAddress.sll_ifindex = getInterfaceIndexInternal(sock, interfaceName);
  if (socketAddress.sll_ifindex == -1) {
    return -1;
  }

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
  /* TODO: larger? */
  return ETHER_MAX_LEN;
}

static int extractPacket(char * const bufbase, size_t limit, int o, int *basep, int *lenp) {
  *basep = 0;
  *lenp = (o == 0) ? limit : 0;
  return limit;
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

static int extractPacket(char *bufbase, size_t limit, int o, int *basep, int *lenp)
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
  char *buf;
  int blen;
  int bytes_read;
};

static void *do_actual_read(void *read_args) {
  struct ReadArgs *args = (struct ReadArgs *) read_args;
  args->bytes_read = read(args->sock, args->buf, args->blen);
  if (args->bytes_read == -1) {
    perror("packet-socket read");
  }
  //scheme_signal_received();
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
  pthread_t read_thread;
  Scheme_Object *result = scheme_null;

  read_args = calloc(1, sizeof(*read_args));
  if (read_args == NULL) {
    perror("socket-read calloc");
    return scheme_false;
  }

  read_args->sock = SCHEME_INT_VAL(argv[0]);
  read_args->buf =  SCHEME_BYTE_STR_VAL(argv[1]);
  read_args->blen = SCHEME_BYTE_STRLEN_VAL(argv[1]);
  read_args->bytes_read = 0;

  /* printf("original thread sock: %d, buf: %p, len: %d\n", */
  /* 	 read_args.sock, */
  /* 	 read_args.buf, */
  /* 	 read_args.blen); */
  /* fflush(NULL); */

  pthread_create(&read_thread, NULL, do_actual_read, read_args);
  scheme_block_until(is_read_done, prepare_for_sleep, (Scheme_Object *) read_args, 0);

  {
    int extractionState = 0;
    int baseOffset = 0;
    int length = 0;

    do {
      extractionState = extractPacket(read_args->buf, read_args->bytes_read, extractionState,
				      &baseOffset,
				      &length);
      result = scheme_make_pair(scheme_make_pair(scheme_make_integer(baseOffset),
						 scheme_make_integer(length)),
				result);
    } while (extractionState < read_args->bytes_read);
  }

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

  scheme_finish_primitive_module(module_env);
  return scheme_void;
}

Scheme_Object *scheme_initialize(Scheme_Env *env) {
  scheme_reload(env);
}

Scheme_Object *scheme_module_name() {
  return scheme_intern_symbol("packet-socket-extension");
}
