
NAME=$1
echo $NAME

sh start_eval_container.sh $NAME
docker exec -it "${NAME}_container" /bin/bash