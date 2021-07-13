#!/usr/bin/env bash

sh delete_eval_container.sh libjpeg
sh start_eval_container.sh libjpeg
docker exec -it "${NAME}_container" "cd /cov/ && ./coverage_seeds.py -t libjpeg"
