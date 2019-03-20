#!/bin/sh

export GCC_SPECS=/usr/share/gcc/hardenednopie.specs
make clean
make
