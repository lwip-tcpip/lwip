# Makefile for UDP iPerf2 Test Tool
#
# Targets:
#   make          - build for native (x86/arm, whatever you're on)
#   make pi       - cross-compile for Raspberry Pi (arm-linux-gnueabihf)
#   make clean    - remove build artifacts
#
# For Raspberry Pi native build: just copy files to Pi and run 'make'

CC       ?= gcc
CFLAGS   := -O2 -Wall -Wextra -std=c99
LDFLAGS  := -lm
TARGET   := udp_iperf_test

# Cross-compile for Raspberry Pi (from x86)
PI_CC    := arm-linux-gnueabihf-gcc

.PHONY: all pi clean help

all: $(TARGET)

$(TARGET): udp_iperf_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo ""
	@echo "Build OK: ./$(TARGET)"
	@echo "  Server: ./$(TARGET) -s"
	@echo "  Client: ./$(TARGET) -c <ip> -b 100M -t 10"

pi: udp_iperf_test.c
	$(PI_CC) $(CFLAGS) -o $(TARGET)_pi $< $(LDFLAGS)
	@echo ""
	@echo "Cross-compiled for Pi: ./$(TARGET)_pi"
	@echo "Copy to Pi: scp $(TARGET)_pi pi@<pi_ip>:~/"

clean:
	rm -f $(TARGET) $(TARGET)_pi

help:
	@echo "Usage:"
	@echo "  make       - build for current platform"
	@echo "  make pi    - cross-compile for Raspberry Pi ARM"
	@echo "  make clean - remove binaries"
