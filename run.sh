#!/bin/sh
docker build -t rawhttp . && docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -p 8080:80 rawhttp
