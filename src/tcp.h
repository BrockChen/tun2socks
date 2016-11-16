// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: tcp.h
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-12 15:37:38
//                  tcp header for big Endian hosts
// 0---------------------------15-----------------------------31----
// |       Source Port         |         Destination Port     |  ^
// +---------------------------+------------------------------+  |
// |                    Sequence Number                       |  |
// +----------------------------------------------------------+  |
// |            Acknowledgment Number (if ACK set)            | 20 bytes
// +-----+-----+C+E+U+A+P+R+S+F+------------------------------+  |
// |thl reservedW|C|R|C|S|S|Y|I|          Window              |  |
// +-----+-----+R+E+G+K+H+T+N+N+------------------------------+  |
// |        Checksum           |        Urgent Pointer        |  v
// +---------------------------+------------------------------+ ----
// |                    Options(if exist)                     |
// +----------------------------------------------------------+
// |                       payload                            |
// +----------------------------------------------------------+
//

#ifndef TCP_H_
#define TCP_H_

#include <stdint.h>
#include "define.h"  // NOLINT

// TCP头部，总长度20字节
struct tcp_hdr {
  uint16_t sport;          // 源端口号
  uint16_t dport;          // 目的端口号
  uint32_t seq;            // 序列号
  uint32_t ack_seq;        // 确认号
  uint8_t reserved : 4;    // 保留6位中的4位首部长度
  uint8_t thl : 4;         // tcp头部长度
  uint8_t fin : 1,         // 8位标志
    syn : 1,
    rst : 1,
    psh : 1,
    ack : 1,
    urg : 1,
    ece : 1,
    cwr : 1;
  uint16_t wsize;          // 16位窗口大小
  uint16_t csum;           // 16位TCP检验和
  uint16_t urp;            // 16为紧急指针
} __attribute__((packed));


void input_tcp_segment();



#endif  // TCP_H_

