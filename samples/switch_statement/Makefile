all:
	clang -Wall -Weverything -g switch_statement.c \
	     -o switch_statement && \
		echo -e "a\0" \
		| valgrind -s ./switch_statement