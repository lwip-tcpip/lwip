#!/bin/bash

cd contrib/ports/unix/check

#build and run unit tests
make clean all

# Build test using make, this tests the Makefile toolchain
make check -j 4
ERR=$?
echo Return value from unittests: $ERR
if [ $ERR != 0 ]; then
       echo "unittests build failed"
       exit 33
fi

# Build example_app using cmake, this tests the CMake toolchain
cd ../../../../
# Copy lwipcfg for example app
cp contrib/examples/example_app/lwipcfg.h.travis contrib/examples/example_app/lwipcfg.h

# Generate CMake
mkdir build
cd build
/usr/local/bin/cmake .. -G Ninja
ERR=$?
echo Return value from cmake generate: $ERR
if [ $ERR != 0 ]; then
       echo "cmake GENERATE failed"
       exit 33
fi

# Build CMake
/usr/local/bin/cmake --build .
ERR=$?
echo Return value from build: $ERR
if [ $ERR != 0 ]; then
       echo "cmake build failed"
       exit 33
fi

# Build docs
/usr/local/bin/cmake --build . --target lwipdocs
ERR=$?
echo Return value from lwipdocs: $ERR
if [ $ERR != 0 ]; then
       echo "lwIP documentation failed"
       exit 33
fi

# Test different lwipopts.h
cd ..
cd contrib/ports/unix/example_app
./iteropts.sh
ERR=$?
echo Return value from iteropts: $ERR
if [ $ERR != 0 ]; then
       echo "lwIP iteropts test failed"
       exit 33
fi
