#!/bin/bash

cd contrib/ports/unix/check
#build and run unit tests
make clean all
ERR=$?
if [ $ERR != 0 ]; then
       echo "unittests build failed"
       exit 33
fi
# Build test using make, this tests the Makefile toolchain
make check -j 4


# Build example_app using cmake, this tests the CMake toolchain
cd ../../../../
# Copy lwipcfg for example app
cp contrib/examples/example_app/lwipcfg.h.travis contrib/examples/example_app/lwipcfg.h

# Generate CMake
mkdir build
cd build
/usr/local/bin/cmake .. -G Ninja

# Build CMake
ERR=$?
if [ $ERR != 0 ]; then
       echo "cmake GENERATE failed"
       exit 33
fi
/usr/local/bin/cmake --build .
ERR=$?
if [ $ERR != 0 ]; then
       echo "cmake build failed"
       exit 33
fi

/usr/local/bin/cmake --build . --target lwipdocs
ERR=$?
if [ $ERR != 0 ]; then
       echo "lwIP documentation failed"
       exit 33
fi

cd ..
cd contrib/ports/unix/example_app
./iteropts.sh
