all:
	clang -Wall -Weverything -g uncontrolled_format_string.c \
	     -o uncontrolled_format_string && \
		echo -e "a\0" \
		| valgrind -s ./uncontrolled_format_string