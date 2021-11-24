#!/usr/bin/env bash
set -euo pipefail

mkdir tmp/seeds
curl https://ruhr-uni-bochum.sciebo.de/s/7sfECFTqcv3dIMe/download > /tmp/seeds.zip
unzip -q -d tmp/seeds /tmp/seeds.zip
rm /tmp/seeds.zip
