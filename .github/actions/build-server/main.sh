#!/bin/sh -e

git config --global --add safe.directory "$(pwd)"

cd server

make setup-go-work build-linux-amd64
