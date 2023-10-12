#!/usr/bin/env bash

cp contrib/examples/example_app/lwipcfg.h.ci contrib/examples/example_app/lwipcfg.h
make -C contrib/ports/unix/check
mkdir build && cd build && cmake .. -G Ninja && cmake --build .
