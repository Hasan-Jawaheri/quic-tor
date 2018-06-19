#include "quicsock/quicsock_alarm.h"

#include "base/logging.h"
#include "net/quic/quic_time.h"

namespace quicsock {

QuicSockAlarm::QuicSockAlarm(const net::QuicClock* clock,
        net::QuicAlarm::Delegate* delegate, QuicSockEventHandler *event_handler)
        : net::QuicAlarm(delegate),
          clock_(clock),
          event_handler_(event_handler),
          alarm_registered_(false),
          alarm_id_(0) {}

QuicSockAlarm::~QuicSockAlarm() {
  CancelImpl();
}

void QuicSockAlarm::SetImpl() {
  DCHECK(deadline().IsInitialized());
  DCHECK(event_handler_ != nullptr);

  DCHECK(!alarm_registered_);

  net::QuicTime::Delta duration = deadline().Subtract(clock_->ApproximateNow());
  duration = net::QuicTime::Delta::Max(duration, net::QuicTime::Delta::Zero());
  alarm_id_ = event_handler_->RegisterAlarm(duration.ToMicroseconds(), this);
  alarm_registered_ = true;
}

void QuicSockAlarm::CancelImpl() {
  DCHECK(!deadline().IsInitialized());
  DCHECK(event_handler_ != nullptr);

  // User may call cancel multiple times.
  if (!alarm_registered_)
    return;

  event_handler_->CancelAlarm(alarm_id_);
  alarm_registered_ = false;
}

void QuicSockAlarm::OnAlarm() {
  if (!alarm_registered_)
    return;

  this->Fire();
}

} // namespace quicsock
