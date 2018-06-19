#ifndef __EVENTFD_UTIL__
#define __EVENTFD_UTIL__

namespace quicsock {
  /**
   * @brief Create a new eventfd for the given connection.
   * @return eventfd on success, -1 otherwise with errno set.
   */
  int CreateEventFD();

  /**
   * @brief Add an event to the given eventfd.
   * @param fd The eventfd to add event to.
   * @return true on success, false otherwise.
   */
  bool AddEventToEventFD(int fd);

  /**
   * @brief Remove an event from the given eventfd.
   * @param fd The eventfd to remove event from.
   * @return true on success, false if there is no event on fd.
   */
  bool RemoveEventFromEventFD(int fd);
} // namespace quicsock

#endif /* __EVENTFD_UTIL__ */
