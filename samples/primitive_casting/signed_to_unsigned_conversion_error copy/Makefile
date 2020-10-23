all:
	clang -Wall -Weverything -g signed_to_unsigned_conversion_error.c \
	     -o signed_to_unsigned_conversion_error && \
		echo -e "-5\0" \
		| valgrind -s ./signed_to_unsigned_conversion_error