#!/usr/bin/env bash
set -euo pipefail

curl https://ruhr-uni-bochum.sciebo.de/s/VtbPOEflB38W5Tz/download > tmp/bla.zip
(cd tmp && unzip -q bla.zip)
rm tmp/bla.zip
