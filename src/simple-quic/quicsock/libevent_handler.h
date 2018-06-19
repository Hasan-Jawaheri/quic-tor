#ifndef __LIBEVENT_HANDLER_H__
#define __LIBEVENT_HANDLER_H__

#include <event.h>
#include <pthread.h>
#include <stdint.h>

#include <map>

#include "quicsock/quicsock_event_handler.h"

namespace quicsock {

class LibEventHandler : public QuicSockEventHandler {
  public:
    LibEventHandler(struct event_base *base);
    virtual ~LibEventHandler();

    // Override QuicSockEventHandler
    virtual AlarmID RegisterAlarm(int64_t microseconds,
        AlarmCallback *callback) override;
    virtual bool CancelAlarm(AlarmID alarm_id) override;
    virtual void CancelAllAlarms() override;
    virtual bool WaitForSocketEvents(int fd, int event_flags,
        int64_t microseconds, SocketCallback *callback) override;

    // AlarmArgs to be passed to the libevent callback.
    class AlarmArgs {
      public:
        LibEventHandler *alarm_handler;
        AlarmID alarm_id;
    };

    // SocketArgs to be apssed to the libevent callback.
    class SocketArgs {
      public:
        SocketCallback *callback;
        struct event_base *base;
    };

    // Execute user alarm callback for alarm associated with alarm_id.
    void ExecuteAlarmCallback(AlarmID alarm_id);

  private:
    // The event base. Not owned by us.
    struct event_base *base_;

    AlarmID next_alarm_id_;

    // Map AlarmID to event struct.
    typedef std::map<AlarmID, struct event*> AlarmEventMap;
    AlarmEventMap alarm_event_map_;

    // Map AlarmID to callback.
    typedef std::map<AlarmID, AlarmCallback*> AlarmCallbackMap;
    AlarmCallbackMap alarm_callback_map_;

    // Map AlarmID to deadline.
    typedef std::map<AlarmID, int64_t> AlarmDeadlineMap;
    AlarmDeadlineMap alarm_deadline_map_;
};

} // namespace quicsock

#endif /* __LIBEVENT_HANDLER_H__ */
