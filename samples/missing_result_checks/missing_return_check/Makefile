all:
	clang -Wall -Weverything -g missing_return_check.c \
	     -o missing_return_check && \
		echo -e "127.0.0.1\0" \
		| valgrind -s ./missing_return_check