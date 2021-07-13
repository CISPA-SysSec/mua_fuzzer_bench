#!/usr/bin/env bash

# running the subjects, some have a different name for the container and the actual execution, hence the tuples
# first element of tuple is container name, second is name for execution
for NAME in "woff2 woff2_base" "woff2 woff2_new" "libjpeg libjpeg" "guetzli guetzli" "aspell aspell" "cares cares_name" "cares cares_parse_reply" "re2 re2" "vorbis vorbis"
do
  set -- $NAME
  echo "${1} ${2}"
  sh delete_eval_container.sh $1
  sh start_eval_container.sh $1
  docker exec -it "${1}_container" bash -c "cd /cov/ && ./coverage_seeds.py -t ${2}" | tee cov/log_${2}.txt
  sh delete_eval_container.sh $1
done