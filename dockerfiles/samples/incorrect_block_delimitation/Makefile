all:
	clang -Wall -Weverything -g incorrect_block_delimitation.c \
	     -o incorrect_block_delimitation && \
		echo -e "a\0" \
		| valgrind -s ./incorrect_block_delimitation