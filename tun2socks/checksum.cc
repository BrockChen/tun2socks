// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: checksum.cc
// 特别要注意，wireshark收到的checksum可能不对，因为比较新的网络硬件
// 可以执行一些高级功能，如IP、TCP检验和计算，这被成为checksum offloading
// 所以对于从本机发出去的网络包，在达到硬件之前,只是简单将校验和字段留空或
// 填入无效信息，交给硬件计算。所以此时wireshak抓到的包中的checksum是不对的
// 要验证这个方法，可以用收到的数据包来计算。
// 也可以通过wireshark的edit -> preferences -> protocols
// -> tcp -> validate checksum if possible 勾上，就可以显示正确的checksum
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-14 15:02:39


#include "tun2socks/checksum.h"  // NOLINT
#include <string.h>
#include <stdlib.h>



int checksum(const uint16_t* buf, int len) {
  int checksum = 0;

  for (int i = 0; i < len; i++) {
    checksum += buf[i];
  }
  checksum = (checksum>>16) + (checksum & 0xffff);  // 将高16bit与低16bit相加
  checksum += (checksum>>16);  // 将进位到高位的16bit与低16bit 再相加
  checksum = 0xffff - checksum;
  return checksum;
}

// 1、  把校验和字段置为0；
// 2、  对IP头部中的每16bit进行二进制求和；
// 3、  如果和的高16bit不为0，则将和的高16bit和低16bit反复相加，
//      直到和的高16bit为0，从而获得一个16bit的值；
// 4、  将该16bit的值取反，存入校验和字段。
int ip_checksum(const uint8_t * packets, int len) {
  if (len < 20) {
    return 0;
  }
  uint16_t buf[10] = {0};
  for (int i = 0; i < 10; i++) {
    buf[i] = (packets[i*2] << 8) + packets[i*2+1];
  }
  buf[5] = 0;
  return checksum(buf, 10);
}



// 把伪首部、TCP报头、TCP数据分为16位的字，如果总长度为奇数个字节，
// 则在最后增添一个位都为0的字节。
// 把TCP报头中的校验和字段置为0
// 其次，用反码相加法累加所有的16位字（进位也要累加）。
// 最后，对计算结果取反，作为TCP的校验和。
int tcp_checksum(const uint8_t* packet, int len,
                 uint32_t srcaddr, uint32_t dstaddr) {
  if (len < 20) {
    return 0;
  }

  // 如果总长度为奇数个字节，则在最后增添一个位都为0的字节
  int total_len = len+12;
  if (total_len % 2 != 0) {
    total_len += 1;
  }

  // 增加12个字节的伪首部：src address,dst addrss,zeros, protocol, tcp len
  uint8_t* p = reinterpret_cast<uint8_t*>(malloc(total_len));
  memset(p, 0, total_len);
  uint32_t* saddr = reinterpret_cast<uint32_t*>(p);
  *saddr = htonl(srcaddr);
  uint32_t* daddr = reinterpret_cast<uint32_t*>(p+4);
  *daddr = htonl(dstaddr);

  p[8] = 0;
  p[9] = TCP_PROTOCOL;
  uint16_t* plen = reinterpret_cast<uint16_t*>(p+10);
  *plen = htons(len);

  memcpy(p+12, packet, len);

  for (int i = 0; i < total_len; i++) {
    printf("%02x ", p[i]);
  }
  printf("\n");
  // 把伪首部、TCP报头、TCP数据分为16位的字
  uint16_t buf[100] = {0};
  for (int i = 0; i < total_len / 2; i++) {
    buf[i] = (p[i*2] << 8) + p[i*2+1];
  }

  free(p);
  // checksum设置成0
  buf[14] = 0;

  for (int i = 0; i < total_len / 2; i++) {
    printf("%04x ", buf[i]);
  }
  printf("\n");

  return checksum(buf, total_len/2);
}


