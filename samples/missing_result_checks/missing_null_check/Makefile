all:
	clang -Wall -Weverything -g missing_null_check.c \
	     -o missing_null_check && \
		echo -e "127.0.0.1\0" \
		| valgrind -s ./missing_null_check