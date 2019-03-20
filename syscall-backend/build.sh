#!/bin/sh

export GCC_SPECS=/usr/share/gcc/hardenednopie.specs
cd network
make clean
make
cd ../storage
make clean
make
cd ..
