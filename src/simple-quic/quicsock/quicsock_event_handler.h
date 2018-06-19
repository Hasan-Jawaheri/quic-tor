/**
 * @brief Abstract handle to allow QuicSock to register events and alarms with
 *        an external event management system.
 */

#ifndef __QUICSOCK_EVENT_HANDLER_H__
#define __QUICSOCK_EVENT_HANDLER_H__

#include <stdbool.h>
#include <stdint.h>

// Socket event flags.
#define QS_EV_TIMEOUT      0x01
#define QS_EV_READ         0x02
#define QS_EV_WRITE        0x04
#define QS_EV_SIGNAL       0x08
#define QS_EV_PERSIST      0x10

namespace quicsock {

class QuicSockEventHandler {
  public:
    virtual ~QuicSockEventHandler() {};

    // Callback for alarm.
    class AlarmCallback {
      public:
        virtual void OnAlarm() = 0;
    };

    // ID for each registered alarm.
    typedef int64_t AlarmID;

    /**
     * @brief Registers a one time alarm to be fired after microseconds.
     * @param microseconds The amount of time to wait.
     * @param callback The callback to execute when the alarm fires.
     * @return An AlarmID used to identify the alarm. Use it to cancel the
     *         alarm.
     */
    virtual AlarmID RegisterAlarm(int64_t microseconds,
        AlarmCallback *callback) = 0;

    /**
     * @brief Cancels a previously registered alarm.
     * @param alarm_id ID of a previously registered alarm.
     * @return true on success, false otherwise.
     */
    virtual bool CancelAlarm(AlarmID alarm_id) = 0;

    /**
     * @brief Cancels all registered alarms.
     */
    virtual void CancelAllAlarms() = 0;

    // Callback for socket events.
    class SocketCallback {
      public:
        virtual void OnCanRead(int fd) = 0;
        virtual void OnCanWrite(int fd) = 0;
    };

    /**
     * @brief Monitor events on fd and execute callbacks for the given time
              period.
     * @param fd The socket to monitor.
     * @param event_flags Flags to control what events to monitor.
     * @param microseconds The maximum number of microsends to wait for.
     * @param callback The callback to use.
     * @return Returns true after successfully waiting for events. On error,
     *         false is returned immediately.
     */
    virtual bool WaitForSocketEvents(int fd, int event_flags,
        int64_t microseconds, SocketCallback *callback) = 0;
};

} // namespace quicsock

#endif /* __QUICSOCK_EVENT_HANDLER_H__ */
