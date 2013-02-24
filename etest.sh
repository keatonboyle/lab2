#!/bin/bash

gcc -o osprdencrypt osprdencrypt.c

echo "Echoing foo into a"

echo foo | ./osprdaccess -w /dev/osprda

echo "Encrypting /dev/osprda with password pass"
./osprdencrypt /dev/osprda . pass sillycrypt 
