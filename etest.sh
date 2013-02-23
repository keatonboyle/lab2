#!/bin/bash

gcc -o osprdencrypt osprdencrypt.c

./osprdencrypt /dev/osprda . pass blowfish
