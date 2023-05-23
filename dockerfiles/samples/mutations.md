-   :white_check_mark: remove/modify bounds (over/under) checks
    - done in cwe 119
-   :white_check_mark: remove/modify size checks (off by one, change constant factor)
    - done in cwe 119
-   :white_check_mark: change sizeof argument (remove field access to struct and replace with whole struct or pointer of struct)
-   :white_check_mark: remove locking mechanisms (`pthread_mutex_lock`)
-   :white_check_mark: remove initialization of variables
-   :white_check_mark: remove braces after if condition
-   :white_check_mark: remove breaks in switch case
-   :white_check_mark: remove default case
-   :white_check_mark: change calculation of read/write address/index (arithmetic with array index, over increment loop index)
-   :white_check_mark: change type of variable/function returns values to be much smaller (long/int -> short?), change signedness, sign extension by changing to larger type (short -> unsigned integer), casting from signed to unsigned and from unsigned to signed
-   :white_check_mark: transfer format string control to user data
-   :white_check_mark: remove null checks / failure checks (also from pointer dereference)
-   :white_check_mark: remove check of function return value
-   :white_check_mark: exchange compare with assignment and reverse
-   change operator precedence
-   modify length value calculation / add/reduce constant
-   remove disabling of signal handler (needed for uninterrupted execution of atomic code and when running non-reentrant signal handlers)
-   remove/insert/move frees, deletes (adding/moving frees are only interesting if they are in in different parts of the control flow)
-   throw a more generic exception than needed
-   remove exception handling, change to generic exception class
-   for `wchar_t` exchange wcslen with strlen (need to find all interesting functions)
-   replace functions with their inherently dangerous alternatives (gets, >> operator)
    - scanf, strcpy, gets, strcpy, (also using argv directly) ...
-   change length based functions to null termination based functions (strncpy -> strcpy)?
-   iterator invalidation
-   loops or copy function arguments should depend on size of user controlled buffer not size of internal buffer
-   arithmetic opertions with the size / use pointer to variable as argument of sizeof
-   modify size argument (need to collect interesting functions)?