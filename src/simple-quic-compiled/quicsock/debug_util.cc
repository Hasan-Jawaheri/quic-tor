#include "quicsock/debug_util.h"

#include <execinfo.h>
#include <stdlib.h>

#include "base/logging.h"

namespace quicsock {
  
void PrintStackTrace() {
  void *array[20];
  size_t size;
  char **strings;
  size_t i;

  size = backtrace(array, 20);
  strings = backtrace_symbols(array, size);

  LOG(ERROR) << "Obtained " << size << " stack frames.";

  for (i = 0; i < size; i++)
    LOG(ERROR) << strings[i];

  free(strings);
}

} // namespace quicsock
