#!/bin/bash

echo "Building the ebpf-mon container...!"
make build

sleep 4s

echo "Removing the old container instance...!"
docker rm -f ebpf-mon
sleep 2

echo "Running the newly built container...!"
make run
