# Threading libraries:

- pthread
  - done
- threads.h
  - not supported by clang?
- g_thread_init() / g_thread_create()
- fork (share memory using fork but how is synchonization done?)
- atomics
  - done compare_exchange as mutex
  - done using fetch_add
- boost (https://www.boost.org/doc/libs/1_74_0/doc/html/thread.html)
- https://docs.microsoft.com/en-us/windows/win32/sync/slim-reader-writer--srw--locks?redirectedfrom=MSDN
- https://docs.microsoft.com/en-us/windows/win32/sync/condition-variables?redirectedfrom=MSDN
