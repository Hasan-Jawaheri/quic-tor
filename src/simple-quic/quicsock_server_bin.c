#include "quicsock/quicsock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <event.h>

#define PORT 6121
#define BUF_SIZE 512

typedef struct {
  struct event_base *base; // Don't own
  quicsock_t qs; // Don't own
} qs_libevent_args_s;

static const char *CERT_FILE = "certs/out/leaf_cert.pem";
static const char *KEY_FILE = "certs/out/leaf_cert.key";

static void read_cb(const int sock, short int event_type, void* varg) {
  if (event_type & EV_READ) {
    quicsock_t qs = (quicsock_t) varg;
    char buf[512];
    memset(buf, 0, sizeof(char) * 512);
    ssize_t rc;
    while ((rc = qs_recv(qs, buf, 512)) > 0) {
      printf("Received(%ld): %s\n", rc, buf);
      qs_send(qs, (void*) buf, rc, 1);
    }
  }
}

static void accept_cb(const int sock, short int event_type, void* varg) {
  qs_libevent_args_s *args = (qs_libevent_args_s*) varg;

  quicsock_t qs = args->qs;
  struct event_base *base = args->base;

  if (event_type & EV_READ) {
    struct sockaddr_storage peer;
    socklen_t addrlen = sizeof(struct sockaddr_storage);

    quicsock_t new_qs = qs_accept(qs, (struct sockaddr*) &peer, &addrlen);
    if (new_qs == INVALID_QUICSOCK) {
      fprintf(stderr, "Accept returned NULL\n");
      return;
    }

    printf("Accept eventfd=%d\n", qs_get_fd(new_qs));

    // Set up data listen event
    // TODO(kku): Need to free this. Should put in libevnt_args struct.
    struct event *read_event = event_new(base, qs_get_fd(new_qs),
        EV_READ|EV_PERSIST, read_cb, (void*) new_qs);
    // Timeout of 50000 microseconds recommended by QUIC.
    struct timeval timeout = {0, 50 * 1000};
    event_add(read_event, &timeout);
  } else if (event_type & EV_TIMEOUT) {
    // Do nothing
  } else {
    fprintf(stderr, "Unknown accept event %d\n", event_type);
  }
}

int main() {
  qs_init(CERT_FILE, KEY_FILE);

  // Set up quicsock
  quicsock_t qs = qs_open();

  struct sockaddr_in si_me;
  memset((char *) &si_me, 0, sizeof(si_me));
  si_me.sin_family = AF_INET;
  si_me.sin_port = htons(PORT);
  si_me.sin_addr.s_addr = htonl(INADDR_ANY);

  if (qs_bind(qs, (struct sockaddr*) &si_me, sizeof(struct sockaddr_in)) != 0) {
    fprintf(stderr, "qs_bind failed\n");
    return 1;
  }
  if (qs_listen(qs) != 0) {
    fprintf(stderr, "qs_listen failed\n");
    return 1;
  }

  // Set up libevent
  event_init();
  struct event_base *base = event_base_new();

  qs_libevent_args_s args;
  args.base = base;
  args.qs = qs;

  struct timeval timeout = {0, 50 * 1000};
  struct event *accept_event = event_new(base, qs_get_fd(qs),
      EV_READ|EV_PERSIST, accept_cb, (void*) &args);
  event_add(accept_event, &timeout);

  /* Enter the event loop; does not return. */
  event_base_dispatch(base);

  event_del(accept_event);
  event_base_free(base);
  qs_close(qs);

  return 0;
}
