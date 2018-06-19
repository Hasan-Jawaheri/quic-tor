#include "quicsock/libevent_handler.h"

#include "base/logging.h"

namespace quicsock {

// Wrappers for libevent callback.
static void OnAlarm(int nothing, short int event_type, void *vargs) {
  LibEventHandler::AlarmArgs *args = (LibEventHandler::AlarmArgs*) vargs;
  LibEventHandler::AlarmID alarm_id = args->alarm_id;
  LibEventHandler *alarm_handler = args->alarm_handler;

  DVLOG(1) << "OnAlarm alarm " << alarm_id;
 
  alarm_handler->ExecuteAlarmCallback(alarm_id);
  delete args;
}

static void OnSocketEvent(int fd, short int event_type, void *vargs) {
  LibEventHandler::SocketArgs *args = (LibEventHandler::SocketArgs*) vargs;

  // Check if our time is up.
  if (event_type & EV_TIMEOUT) {
    event_base_loopexit(args->base, NULL);
    return;
  }

  DCHECK(args->callback != nullptr);
  if (event_type & EV_READ) {
    args->callback->OnCanRead(fd);
  } else if (event_type & EV_WRITE) {
    args->callback->OnCanWrite(fd);
  }
}

LibEventHandler::LibEventHandler(struct event_base *base)
    : base_(base), next_alarm_id_(0) {}

LibEventHandler::~LibEventHandler() {
  // TODO(kku): Free stuff.
}

QuicSockEventHandler::AlarmID LibEventHandler::RegisterAlarm(
    int64_t microseconds, AlarmCallback *callback) {
  DCHECK(base_ != nullptr);
  AlarmID alarm_id = next_alarm_id_;
  next_alarm_id_++;

  alarm_callback_map_.insert(std::make_pair(alarm_id, callback));
  alarm_deadline_map_.insert(std::make_pair(alarm_id, microseconds));

  AlarmArgs *args = new AlarmArgs();
  args->alarm_handler = this;
  args->alarm_id = alarm_id;

  struct event *alarm_event = evtimer_new(base_, &OnAlarm, (void*) args);
  struct timeval alarm_tv = {0, microseconds};
  evtimer_add(alarm_event, &alarm_tv);

  alarm_event_map_.insert(std::make_pair(alarm_id, alarm_event));

  DVLOG(1) << "Registered alarm " << alarm_id << " duration: "
      << microseconds << " us";
  return alarm_id;
}

bool LibEventHandler::CancelAlarm(AlarmID alarm_id) {
  DVLOG(1) << "Canceling alarm " << alarm_id;

  AlarmEventMap::iterator event_it = alarm_event_map_.find(alarm_id); 
  if (event_it == alarm_event_map_.end()) {
    LOG(ERROR) << "Cannot find alarm event for alarm id " << alarm_id;
    return false;
  }

  evtimer_del(event_it->second);
  event_free(event_it->second);
  alarm_event_map_.erase(event_it);
  alarm_deadline_map_.erase(alarm_id);

  AlarmCallbackMap::iterator callback_it = alarm_callback_map_.find(alarm_id);
  if (callback_it == alarm_callback_map_.end()) {
    LOG(ERROR) << "Cannot find callback for alarm id " << alarm_id;
    return false;
  }
  alarm_callback_map_.erase(callback_it);
  return true;
}

void LibEventHandler::CancelAllAlarms() {
  DVLOG(1) << "Canceling all alarms";

  // Unregister all events.
  AlarmEventMap::iterator event_it;
  for (event_it = alarm_event_map_.begin();
      event_it != alarm_event_map_.end();
      event_it++) {
    evtimer_del(event_it->second);
    event_free(event_it->second);
  }
  alarm_event_map_.clear();
  alarm_deadline_map_.clear();

  // Remove all callbacks.
  alarm_callback_map_.clear();
}

bool LibEventHandler::WaitForSocketEvents(int fd, int event_flags,
    int64_t microseconds, SocketCallback *callback) {
  DCHECK(base_ != nullptr);

  if (callback == nullptr) {
    LOG(ERROR) << "NULL callback passed to WaitForSocketEvents";
    return false;
  }

  DVLOG(1) << "Waiting for events on fd=" << fd << " for " << microseconds
      << "us";

  SocketArgs args;
  args.callback = callback;
  args.base = base_;

  int libevent_flags = 0;
  if (event_flags & QS_EV_READ)
    libevent_flags |= EV_READ;
  if (event_flags & QS_EV_WRITE)
    libevent_flags |= EV_WRITE;
  // Make sure we have timeout and persist events.
  libevent_flags |= EV_TIMEOUT;
  libevent_flags |= EV_PERSIST;
  libevent_flags |= EV_ET;
  struct event *sock_event = event_new(base_, fd, libevent_flags,
      OnSocketEvent, (void*) &args);
  struct timeval timeout = {0, microseconds};
  event_add(sock_event, &timeout);

  event_base_dispatch(base_);

  DVLOG(1) << "Finished waiting events for fd=" << fd;
  event_del(sock_event);
  event_free(sock_event);

  return true;
}

void LibEventHandler::ExecuteAlarmCallback(AlarmID alarm_id) {
  AlarmCallbackMap::iterator callback_it = alarm_callback_map_.find(alarm_id);
  if (callback_it == alarm_callback_map_.end()) {
    // TODO(kku): We are not removing events from libevent, so if the callback
    // is not present it means that the alarm is canceled.
    // LOG(ERROR) << "Cannot find callback for alarm id " << alarm_id;
    return;
  }
  
  callback_it->second->OnAlarm();
}

} // namespace quicsock
