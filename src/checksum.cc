// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: checksum.cc
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-14 15:02:39


#include "checksum.h"  // NOLINT
#include <string.h>

// 1、  把校验和字段置为0；
// 2、  对IP头部中的每16bit进行二进制求和；
// 3、  如果和的高16bit不为0，则将和的高16bit和低16bit反复相加，
//      直到和的高16bit为0，从而获得一个16bit的值；
// 4、  将该16bit的值取反，存入校验和字段。
int ip_checksum(uint8_t * packets, int len) {
  if (len < 20) {
    return 0;
  }
  int checksum = 0;
  uint16_t buf[10] = {0};
  for (int i = 0; i < 10; i++) {
    buf[i] = (packets[i*2] << 8) + packets[i*2+1];
  }
  buf[5] = 0;

  for (int i = 0; i < 10; i++) {
    checksum += buf[i];
  }
  checksum = (checksum>>16) + (checksum & 0xffff);  // 将高16bit与低16bit相加
  checksum += (checksum>>16);  // 将进位到高位的16bit与低16bit 再相加
  checksum = 0xffff - checksum;
  return checksum;
}
