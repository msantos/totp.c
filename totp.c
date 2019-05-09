/*
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2015, David M. Syzdek <david@syzdek.net>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *
 *     3. Neither the name of the copyright holder nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 *  Keys are entered in base32 encodings
 *
 *  Compile with:  gcc -Wall -o totp totp.c -lcrypto
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <hmac/hmac.h>

#if defined(SANDBOX_rlimit)
#include <sys/resource.h>
#include <sys/time.h>
#define SANDBOX "rlimit"
#elif defined(SANDBOX_null)
#define SANDBOX "null"
#endif

static const int8_t base32_vals[256] = {
    //    This map cheats and interprets:
    //       - the numeral zero as the letter "O" as in oscar
    //       - the numeral one as the letter "L" as in lima
    //       - the numeral eight as the letter "B" as in bravo
    // 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
    14, 11, 26, 27, 28, 29, 30, 31, 1,  -1, -1, -1, -1, 0,  -1, -1, // 0x30
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, // 0x40
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, // 0x60
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1, // 0x70
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};
// static const char * base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";

int sandbox(void);
int main(int argc, char *argv[]);

int main(int argc, char *argv[]) {
  size_t pos;
  size_t len;
  size_t keylen;
  uint32_t endianness;
  time_t t0;  // Unix time to start counting time step
  uint64_t x; // step in seconds
  uint64_t t; // number of steps
  uint64_t offset;
  uint8_t hmac_result[20] = {0};
  size_t hmac_result_len;
  uint32_t bin_code;
  uint32_t totp;
  uint8_t *k; // user's secret key

  x = 30;
  t0 = 0;

  if (sandbox() < 0) {
    fprintf(stderr, "error: sandbox: %s\n", strerror(errno));
    return (111);
  }

  switch (argc) {
  case 4:
    t0 = strtoll(argv[3], NULL, 0);

  case 3:
    x = strtoll(argv[2], NULL, 0);

  case 2:
    k = (uint8_t *)argv[1];
    break;

  default:
    fprintf(
        stderr,
        "Usage: %s <b32_key> [ <interval> [ <start> ] ]\n(using %s sandbox)\n",
        argv[0], SANDBOX);
    return (1);
    break;
  };

  len = strlen(argv[1]);

  // validates base32 key
  if (((len & 0xF) != 0) && ((len & 0xF) != 8)) {
    fprintf(stderr, "%s: invalid base32 secret\n", argv[0]);
    return (1);
  };
  for (pos = 0; (pos < len); pos++) {
    if (base32_vals[k[pos]] == -1) {
      fprintf(stderr, "%s: invalid base32 secret\n", argv[0]);
      return (1);
    };
    if (k[pos] == '=') {
      if (((pos & 0xF) == 0) || ((pos & 0xF) == 8)) {
        fprintf(stderr, "%s: invalid base32 secret\n", argv[0]);
        return (1);
      }
      if ((len - pos) > 6) {
        fprintf(stderr, "%s: invalid base32 secret\n", argv[0]);
        return (1);
      };
      switch (pos % 8) {
      case 2:
      case 4:
      case 5:
      case 7:
        break;

      default:
        fprintf(stderr, "%s: invalid base32 secret\n", argv[0]);
        return (1);
      };
      for (; (pos < len); pos++) {
        if (k[pos] != '=') {
          fprintf(stderr, "%s: invalid base32 secret\n", argv[0]);
          return (1);
        };
      };
    };
  };

  // decodes base32 secret key
  keylen = 0;
  for (pos = 0; pos <= (len - 8); pos += 8) {
    // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
    // MB is middle bits             (0x7E == 01111110 ~= MB)
    // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)

    // byte 0
    k[keylen + 0] = (base32_vals[k[pos + 0]] << 3) & 0xF8;  // 5 MSB
    k[keylen + 0] |= (base32_vals[k[pos + 1]] >> 2) & 0x07; // 3 LSB
    if (k[pos + 2] == '=') {
      keylen += 1;
      break;
    };

    // byte 1
    k[keylen + 1] = (base32_vals[k[pos + 1]] << 6) & 0xC0;  // 2 MSB
    k[keylen + 1] |= (base32_vals[k[pos + 2]] << 1) & 0x3E; // 5  MB
    k[keylen + 1] |= (base32_vals[k[pos + 3]] >> 4) & 0x01; // 1 LSB
    if (k[pos + 4] == '=') {
      keylen += 2;
      break;
    };

    // byte 2
    k[keylen + 2] = (base32_vals[k[pos + 3]] << 4) & 0xF0;  // 4 MSB
    k[keylen + 2] |= (base32_vals[k[pos + 4]] >> 1) & 0x0F; // 4 LSB
    if (k[pos + 5] == '=') {
      keylen += 3;
      break;
    };

    // byte 3
    k[keylen + 3] = (base32_vals[k[pos + 4]] << 7) & 0x80;  // 1 MSB
    k[keylen + 3] |= (base32_vals[k[pos + 5]] << 2) & 0x7C; // 5  MB
    k[keylen + 3] |= (base32_vals[k[pos + 6]] >> 3) & 0x03; // 2 LSB
    if (k[pos + 7] == '=') {
      keylen += 4;
      break;
    };

    // byte 4
    k[keylen + 4] = (base32_vals[k[pos + 6]] << 5) & 0xE0;  // 3 MSB
    k[keylen + 4] |= (base32_vals[k[pos + 7]] >> 0) & 0x1F; // 5 LSB
    keylen += 5;
  };
  k[keylen] = 0;

  t = (time(NULL) - t0) / x;

  // converts T to big endian if system is little endian
  endianness = 0xdeadbeef;
  if ((*(const uint8_t *)&endianness) == 0xef) {
    t = ((t & 0x00000000ffffffff) << 32) | ((t & 0xffffffff00000000) >> 32);
    t = ((t & 0x0000ffff0000ffff) << 16) | ((t & 0xffff0000ffff0000) >> 16);
    t = ((t & 0x00ff00ff00ff00ff) << 8) | ((t & 0xff00ff00ff00ff00) >> 8);
  };

  // determines hash
  hmac_result_len = sizeof(hmac_result);
  hmac_sha1(k, keylen, (const unsigned char *)&t, sizeof(t), hmac_result,
            &hmac_result_len);

  // dynamically truncates hash
  offset = hmac_result[19] & 0x0f;
  bin_code = (hmac_result[offset] & 0x7f) << 24 |
             (hmac_result[offset + 1] & 0xff) << 16 |
             (hmac_result[offset + 2] & 0xff) << 8 |
             (hmac_result[offset + 3] & 0xff);

  // truncates code to 6 digits
  totp = bin_code % 1000000;

  printf("%06u\n", totp);

  return (0);
}

#if defined(SANDBOX_rlimit)
int sandbox() {
  struct rlimit rl_zero = {0};

  if (setrlimit(RLIMIT_NPROC, &rl_zero) < 0)
    return -1;

  if (setrlimit(RLIMIT_NOFILE, &rl_zero) < 0)
    return -1;

  return setrlimit(RLIMIT_FSIZE, &rl_zero);
}
#elif defined(SANDBOX_null)
int sandbox() { return 0; }
#endif
