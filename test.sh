#!/bin/bash

if [ "$COMPILER" ];
then
	export CC=$COMPILER
fi
cd contrib/ports/unix/check
#build and run unit tests
make clean all
ERR=$?
if [ $ERR != 0 ]; then
       echo "unittests build failed"
       exit 33
fi
make check
