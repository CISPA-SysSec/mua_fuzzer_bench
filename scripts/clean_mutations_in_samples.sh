#!/bin/sh

find samples -name mutations -type d -print
find samples -name '*.mutationlocations' -print
find samples -name '*.ll' -print
find samples -name '*.bc' -print
find samples -name '*.o' -print

find samples -name mutations -type d -exec rm -rf {} +
find samples -name '*.mutationlocations' -delete
find samples -name '*.ll' -delete
find samples -name '*.bc' -delete
find samples -name '*.o' -delete