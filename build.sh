#!/bin/bash
gcc -Wall -shared -fPIC alpha.c -o alpha.so
gcc -g -ldl -Wall main.c -o main
