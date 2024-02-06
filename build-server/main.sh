#!/bin/sh -e

# Allow go VCS stamping
git config --global --add safe.directory "$(pwd)"

cd server
make setup-go-work build-linux-amd64
