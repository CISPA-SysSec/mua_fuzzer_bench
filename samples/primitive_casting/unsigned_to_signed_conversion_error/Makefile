all:
	clang -Wall -Weverything -g unsigned_to_signed_conversion_error.c \
	     -o unsigned_to_signed_conversion_error && \
		echo -e "-5\0" \
		| valgrind -s ./unsigned_to_signed_conversion_error