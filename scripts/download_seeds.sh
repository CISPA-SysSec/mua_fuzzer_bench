#!/usr/bin/env bash
set -euo pipefail

mkdir tmp/seeds
curl https://ruhr-uni-bochum.sciebo.de/s/66e1uvRoYL3FSE1/download > /tmp/seeds.zip
unzip -q -d tmp/seeds /tmp/seeds.zip
rm /tmp/seeds.zip
