#!/bin/bash

LOGFILE=iteropts.log
EXAPPDIR=../../../examples/example_app
RETVAL=0

pushd `dirname "$0"`
pwd
echo Starting Iteropts run >> $LOGFILE
for f in $EXAPPDIR/test_configs/*.h
do
    echo Cleaning...
    make clean > /dev/null
    BUILDLOG=$(basename "$f" ".h").log
    echo testing $f
    echo testing $f >> $LOGFILE
    rm $EXAPPDIR/lwipopts_test.h
    # cat the file to update its timestamp
    cat $f > $EXAPPDIR/lwipopts_test.h
    make TESTFLAGS=-DLWIP_OPTTEST_FILE -j 8 1> $BUILDLOG 2>&1 || (RETVAL=1; echo file $f failed >> $LOGFILE; echo ++++++++ $f FAILED +++++++; cat $BUILDLOG)
    echo test $f done >> $LOGFILE
done
echo done, cleaning
make clean > /dev/null
popd
exit $RETVAL
