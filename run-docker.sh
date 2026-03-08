#!/bin/bash

read -p "Do you want to start the Redis container? (y/N) " REPLY
REPLY=$(echo "$REPLY" | tr '[:upper:]' '[:lower:]')
if [[ $REPLY =~ ^[Yy]$ ]]
then
    docker compose -f docker-compose.redis.yml up -d
    echo "[-] Redis container started"
else
    echo "[-] Redis container not started"
fi

docker compose run --rm emulator bash

pkill python3

# python3 -m emulate ../beanpod/
# clean redis container
docker compose -f docker-compose.redis.yml down

