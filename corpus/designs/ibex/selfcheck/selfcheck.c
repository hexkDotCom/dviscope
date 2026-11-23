// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 HEXK
//
// Self-checking program for the Ibex simple system (DVIScope corpus). Exercises the ALU (XOR,
// shifts, compares), the multiplier and divider, branches and memory, then prints one result
// line and halts. Expected values are computed on the host (corpus/README.md).

#include "simple_system_common.h"

static unsigned crc32_bytes(const unsigned char *p, unsigned n) {
  unsigned crc = 0xFFFFFFFFu;
  for (unsigned i = 0; i < n; i++) {
    crc ^= p[i];
    for (int b = 0; b < 8; b++) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
  }
  return ~crc;
}

int main(void) {
  static unsigned char buf[256];
  static volatile int arr[16];
  unsigned failures = 0;

  for (unsigned i = 0; i < 256; i++) {
    buf[i] = (unsigned char)i;
  }
  if (crc32_bytes(buf, 256) != 0x29058C73u) {
    failures |= 1u;
  }

  volatile unsigned n = 100;
  unsigned sum = 0;
  for (unsigned i = 1; i <= n; i++) {
    sum += i * i;
  }
  if (sum != 338350u) {
    failures |= 2u;
  }

  volatile unsigned num = 1000003u, den = 7u;
  if (num / den != 142857u || num % den != 4u) {
    failures |= 4u;
  }

  unsigned a = 0, b = 1;
  for (int i = 0; i < 30; i++) {
    unsigned t = a + b;
    a = b;
    b = t;
  }
  if (a != 832040u) {
    failures |= 8u;
  }

  for (int i = 0; i < 16; i++) {
    arr[i] = (i * 7 + 3) % 16 - 8;
  }
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j + 1 < 16 - i; j++) {
      if (arr[j] > arr[j + 1]) {
        int t = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = t;
      }
    }
  }
  for (int i = 0; i + 1 < 16; i++) {
    if (arr[i] > arr[i + 1]) {
      failures |= 16u;
    }
  }

  if (failures == 0) {
    puts("SELFCHECK PASSED\n");
  } else {
    puts("SELFCHECK FAILED ");
    puthex(failures);
    puts("\n");
  }
  sim_halt();
  return 0;
}
