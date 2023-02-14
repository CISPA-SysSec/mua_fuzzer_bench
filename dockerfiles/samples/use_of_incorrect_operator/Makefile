all:
	clang -Wall -Weverything -g use_of_incorrect_operator.c \
	     -o use_of_incorrect_operator && \
		echo -e "aaaaasdfasdfAABBAAAAAAA\0" \
		| valgrind -s ./use_of_incorrect_operator
