#ifdef __linux__
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#endif

#include "escheme.h"

#ifdef __linux__

int getInterfaceIndexInternal(int sock, char* interfaceName) {
  struct ifreq *ifr;
  int index_result;

  ifr = (struct ifreq*) malloc(sizeof(struct ifreq));
  strncpy((char *) ifr->ifr_name, interfaceName, IFNAMSIZ);
  /* printf("The interface for index: %s\n", ifr->ifr_name); */

  if (ioctl(sock, SIOCGIFINDEX, ifr) < 0) {
    perror("ioctl error while looking up interface");
    return -1;
  }

  index_result = ifr->ifr_ifindex;
  free(ifr);
  return index_result;
}


int bindToInterface(int sock, char* interfaceName, int index) {
  struct sockaddr_ll socketAddress;

  socketAddress.sll_family = AF_PACKET;
  socketAddress.sll_ifindex = index;
  socketAddress.sll_protocol = htons(ETH_P_ALL);

  if (bind(sock, (struct sockaddr *) &socketAddress, sizeof(struct sockaddr_ll)) < 0) {
    perror("Bind error");
    return -1;
  }

  return 0;
}

void setPromiscuousMode(int sock, int index) {
  struct packet_mreq *req;

  req = (struct packet_mreq*)malloc(sizeof(struct packet_mreq));
  req->mr_ifindex = index;
  req->mr_type = PACKET_MR_PROMISC;

  if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)req, (socklen_t)sizeof(struct packet_mreq)) < 0) {
    perror("set sock opt error");
  }
}

#endif /* def __linux__ */

Scheme_Object *enumerate_interfaces(int argc, Scheme_Object **argv) {
#ifdef __linux__
  Scheme_Object *result = scheme_null;
  struct ifaddrs *addrs;
  struct ifaddrs *tmp;

  if (getifaddrs(&addrs) == -1) {
    perror("getifaddrs");
    return scheme_false;
  }

  for (tmp = addrs; tmp != NULL; tmp = tmp->ifa_next) {
    if (tmp->ifa_addr != NULL && tmp->ifa_addr->sa_family == AF_PACKET) {
      result = scheme_make_pair(scheme_make_utf8_string(tmp->ifa_name), result);
    }
  }

  freeifaddrs(addrs);
  return result;
#endif

#if defined(__APPLE__) && defined(__MACH__)
  return scheme_false;
#endif
}

Scheme_Object *create_and_bind_socket(int argc, Scheme_Object **argv) {
#ifdef __linux__
  int sock, index;
  char *interface_name;

  interface_name = SCHEME_BYTE_STR_VAL(argv[0]);

  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    perror("Socket error");
    return scheme_false;
  }

  index = getInterfaceIndexInternal(sock, interface_name);
  if (index == -1) {
    return scheme_false;
  }

  if (bindToInterface(sock, interface_name, index) == -1) {
    return scheme_false;
  }

  /* setPromiscuousMode(sock, index); */

  return (Scheme_Object*) scheme_make_integer(sock);
#endif

#if defined(__APPLE__) && defined(__MACH__)
  return scheme_false;
#endif
}

Scheme_Object *close_socket(int argc, Scheme_Object **argv) {
#ifdef __linux__
  int sock;
  sock = SCHEME_INT_VAL(argv[0]);

  if (close(sock) < 0) {
    perror("close");
    return scheme_false;
  }

  return scheme_true;
#endif

#if defined(__APPLE__) && defined(__MACH__)
  return scheme_false;
#endif
}

#ifdef __linux__

struct ReadArgs {
  int sock;
  char *buf;
  int blen;
  int *bytes_read;
};

void do_actual_read(void *read_args) {
  struct ReadArgs *args = (struct ReadArgs *)read_args;
  int bytes_read;
  bytes_read = read(args->sock, args->buf, args->blen);
  *(args->bytes_read) = bytes_read;
  scheme_signal_received();
}

int is_read_done(Scheme_Object *data) {
  struct ReadArgs *read_args = (struct ReadArgs*)data;
  return *(read_args->bytes_read) != 0;
}

void prepare_for_sleep(Scheme_Object *data, void *fds) {
  struct ReadArgs *read_args = (struct ReadArgs*)data;

  MZ_FD_SET(read_args->sock, scheme_get_fdset(fds, 1));
}

#endif

Scheme_Object *socket_read(int argc, Scheme_Object **argv) {
#ifdef __linux__
  struct ReadArgs *read_args;
  int *bytes_read;
  pthread_t read_thread;
  int read_count;

  bytes_read = (int*)malloc(sizeof(int));
  *bytes_read = 0;

  read_args = (struct ReadArgs*)malloc(sizeof(struct ReadArgs));
  read_args->sock = SCHEME_INT_VAL(argv[0]);
  read_args->buf =  SCHEME_BYTE_STR_VAL(argv[1]);
  read_args->blen = SCHEME_BYTE_STRLEN_VAL(argv[1]);
  read_args->bytes_read = bytes_read;

  //printf("original thread sock: %d, buf: %p\n", read_args->sock, read_args->buf);
  pthread_create(&read_thread, NULL, do_actual_read, (void*)read_args);

  scheme_block_until(is_read_done, prepare_for_sleep, (Scheme_Object*)read_args, -1);

  read_count = *bytes_read;
  free(read_args);
  free(bytes_read);
  return (Scheme_Object*)scheme_make_integer(read_count);
#endif

#if defined(__APPLE__) && defined(__MACH__)
  return scheme_false;
#endif
}

Scheme_Object *socket_write(int argc, Scheme_Object **argv) {
#ifdef __linux__
  int sock;
  char *buf;
  int blen, bytes_written;

  sock = SCHEME_INT_VAL(argv[0]);
  buf =  SCHEME_BYTE_STR_VAL(argv[1]);
  blen = SCHEME_BYTE_STRLEN_VAL(argv[1]);
  bytes_written = write(sock, buf, blen);
  return (Scheme_Object*)scheme_make_integer(bytes_written);
#endif

#if defined(__APPLE__) && defined(__MACH__)
  return scheme_false;
#endif
}

Scheme_Object *scheme_reload(Scheme_Env *env) {
  Scheme_Env *module_env;
  Scheme_Object *proc, *proc2, *proc3, *read_proc, *write_proc;

  module_env = scheme_primitive_module(scheme_intern_symbol("packet-socket-extension"), env);

  proc = scheme_make_prim_w_arity(enumerate_interfaces, "enumerate-interfaces", 0, 0);
  scheme_add_global("enumerate-interfaces", proc, module_env);

  proc2 = scheme_make_prim_w_arity(close_socket, "socket-close", 1, 1);
  scheme_add_global("close-socket", proc2, module_env);

  proc3 = scheme_make_prim_w_arity(create_and_bind_socket, "create-and-bind-socket", 1, 1);
  scheme_add_global("create-and-bind-socket", proc3, module_env);

  read_proc = scheme_make_prim_w_arity(socket_read, "socket-read", 2, 2);
  scheme_add_global("socket-read", read_proc, module_env);

  write_proc = scheme_make_prim_w_arity(socket_write, "socket-write", 2, 2);
  scheme_add_global("socket-write", write_proc, module_env);

  scheme_finish_primitive_module(module_env);
  return scheme_void;
}

Scheme_Object *scheme_initialize(Scheme_Env *env) {
  scheme_reload(env);
}

Scheme_Object *scheme_module_name() {
  return scheme_intern_symbol("packet-socket-extension");
}
