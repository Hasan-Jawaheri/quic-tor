#ifndef _QUICSOCK_ALARM_H_
#define _QUICSOCK_ALARM_H_

#include <stdbool.h>
#include <stdint.h>

#include "net/quic/quic_alarm.h"
#include "net/quic/quic_clock.h"

#include "quicsock/quicsock_event_handler.h"

namespace quicsock {

class QuicSockAlarm : public net::QuicAlarm,
                      public QuicSockEventHandler::AlarmCallback {
  public:
    QuicSockAlarm(const net::QuicClock* clock,
        net::QuicAlarm::Delegate* delegate,
        QuicSockEventHandler *event_handler);
    ~QuicSockAlarm();

    // QuicSockEventHandler::AlarmCallback
    void OnAlarm() override;

  protected:
    void SetImpl() override;

    void CancelImpl() override;

  private:
    const net::QuicClock* clock_;

    QuicSockEventHandler *event_handler_;

    bool alarm_registered_;

    // ID of registered alarm.
    QuicSockEventHandler::AlarmID alarm_id_;
};

}  // namespace quicsock

#endif /* _QUICSOCK_ALARM_H_ */
