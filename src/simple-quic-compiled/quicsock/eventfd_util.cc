#include "quicsock/eventfd_util.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "base/logging.h"

namespace quicsock {

int CreateEventFD() {
  return eventfd(0, EFD_NONBLOCK|EFD_SEMAPHORE);
}

bool AddEventToEventFD(int fd) {
  if (fd < 0)
    return false;

  DVLOG(1) << "Adding event to eventfd=" << fd;

  uint64_t n = 1;
  if (write(fd, &n, sizeof(uint64_t)) < 0) {
    LOG(ERROR) << "Failed to add event to eventfd " << fd << ": "
        << strerror(errno);
    return false;
  }

  return true;
}

bool RemoveEventFromEventFD(int fd) {
  if (fd < 0)
    return false;

  DVLOG(1) << "Removing event from eventfd=" << fd;

  uint64_t n;
  if (read(fd, &n, sizeof(uint64_t)) < 0) {
    return false;
  }

  return true;
}

} // namesapce quicsock
