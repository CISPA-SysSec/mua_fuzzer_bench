#!/usr/bin/env bash

set -Euo pipefail

( ulimit -Sd $[74 << 10] -t 2; "$@" )