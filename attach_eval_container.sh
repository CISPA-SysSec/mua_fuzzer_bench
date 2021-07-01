
NAME=$1
echo $NAME

docker build -f "subjects/Dockerfile.${NAME}" -t "eval_${NAME}" .
docker run -v $(pwd)/cov:/cov -dt --security-opt seccomp=unconfined --name "${NAME}_container" "eval_${NAME}"
docker start "${NAME}_container"
docker exec -it "${NAME}_container" /bin/bash