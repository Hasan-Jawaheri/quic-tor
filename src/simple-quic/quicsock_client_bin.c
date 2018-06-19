#include "quicsock/quicsock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <event.h>

#define PORT 6121
#define BUF_SIZE 512

static const char *CERT_FILE = "certs/out/leaf_cert.pem";
static const char *KEY_FILE = "certs/out/leaf_cert.key";

static void read_cb(const int sock, short int event_type, void* varg) {
  quicsock_t qs = (quicsock_t) varg;

  if (event_type & EV_READ) {
    // Call user callback.
    printf("Data Callback fd=%d\n", qs_get_fd(qs));
    char buf[512];
    memset(buf, 0, sizeof(char) * 512);
    ssize_t rc;
    while ((rc = qs_recv(qs, buf, 512)) > 0) {
      printf("Received(%ld): %s\n", rc, buf);
    }
  } else if (event_type & EV_TIMEOUT) {
    // Do nothing
  } else {
    fprintf(stderr, "Unknown data event %d\n", event_type);
  }
}

int main() {
  qs_init(CERT_FILE, KEY_FILE);

  // Set up quicsock
  quicsock_t qs = qs_open();

  struct sockaddr_in si_host;
  memset((char *) &si_host, 0, sizeof(si_host));
  si_host.sin_family = AF_INET;
  si_host.sin_port = htons(PORT);

  if (inet_aton("127.0.0.1", &si_host.sin_addr) == 0) {
    fprintf(stderr, "inet_aton() failed\n");
    return 1;
  }

  socklen_t addrlen = sizeof(struct sockaddr_in);
  if (qs_connect(qs, (struct sockaddr*) &si_host, addrlen) != 0) {
    fprintf(stderr, "qs_connect failed\n");
    return 1;
  }

  printf("eventfd=%d\n", qs_get_fd(qs));
  // Add data event
  event_init();
  struct event_base *base = event_base_new();

  // Timeout of 50000 microseconds recommended by QUIC.
  struct timeval timeout = {0, 50 * 1000};
  struct event *read_event = event_new(base, qs_get_fd(qs),
      EV_READ|EV_PERSIST, read_cb, (void*) qs);
  event_add(read_event, &timeout);

  // Send message to server
  char buf[10];
  int i = 0;
  for (i = 0; i < 10; i++) {
    buf[i] = (char) 60 + i;
  }
  qs_send(qs, (void*) buf, 10, 1);
  // qs_send(qs, (void*) "Hello 2", 8, 1);

  /* Enter the event loop; does not return. */
  event_base_dispatch(base);

  event_del(read_event);
  event_base_free(base);
  qs_close(qs);

  return 0;
}
