
NAME=$1
echo $NAME

docker stop "${NAME}_container"
docker rm "${NAME}_container"
docker image rm "eval_${NAME}"