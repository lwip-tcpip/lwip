#!/bin/bash

LOGFILE=iteropts.log
EXAPPDIR=../../../examples/example_app

pushd `dirname "$0"`
pwd
echo Starting Iteropts run >> $LOGFILE
for f in $EXAPPDIR/test_configs/*.h
do
    echo Cleaning...
    make clean
    BUILDLOG=$(basename "$f" ".h").log
    echo testing $f
    echo testing $f >> $LOGFILE
    rm $EXAPPDIR/lwipopts_test.h
    # cat the file to update its timestamp
    cat $f > $EXAPPDIR/lwipopts_test.h
    make TESTFLAGS=-DLWIP_OPTTEST_FILE -j 8 &> $BUILDLOG 2>&1 || echo file $f failed >> $LOGFILE
    echo test $f done >> $LOGFILE
done
echo done, cleaning
make clean
popd
