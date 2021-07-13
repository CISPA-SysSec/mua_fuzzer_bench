#!/usr/bin/env bash

# running libjpeg
sh delete_eval_container.sh libjpeg
sh start_eval_container.sh libjpeg
docker exec -it "libjpeg_container" bash -c "cd /cov/ && ./coverage_seeds.py -t libjpeg" > /cov/log_libjpeg.txt
sh delete_eval_container.sh libjpeg
