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
  uint8_t reserved : 4;    // 保留位
  uint8_t thl : 4;         // tcp头部长度

  // uint8_t flags;           // 8位标志
  uint8_t fin : 1,
    syn : 1,
    rst : 1,
    psh : 1,
    ack : 1,
    urg : 1,
    ece : 1,
    cwr : 1;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS  (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  uint16_t win;            // 16位窗口大小
  uint16_t csum;           // 16位TCP检验和
  uint16_t urp;            // 16为紧急指针
} __attribute__((packed));



struct tcp_segment {
  uint16_t sport;      // 源端口号
  uint16_t dport;      // 目的端口号
  uint32_t seq;        // first sequence number of a segment
  uint32_t ack;        // acknowledgment from the receiving TCP (next
                       // sequence number expected by the receiving TCP)
  uint8_t thl;         // tcp头部长度
  //  uint8_t flags;       // 8位标志
  uint32_t dlen;
  uint32_t len;        // the number of octets occupied by the data in the
                       // segment (counting SYN and FIN)
  uint32_t win;
  uint16_t csum;       // 16位TCP检验和
  uint32_t urp;
  uint32_t prc;        // precedence value, not used
  uint32_t seq_last;   // last sequence number of a segment
};
/*
struct tcp_packet {
  uint16_t sport;          // 源端口号
  uint16_t dport;          // 目的端口号
  uint32_t seq;            // 序列号
  uint32_t ack_seq;        // 确认号
  uint8_t reserved;        // 保留6位中的4位首部长度
  uint8_t thl;             // tcp头部长度
  uint8_t flags;           // 8位标志
  uint16_t win;          // 16位窗口大小
  uint16_t csum;           // 16位TCP检验和
  uint16_t urp;            // 16为紧急指针
  uint8_t* data;
};
*/

extern int parse_tcp(struct ip_packet *ip, int len, struct tcp_segment* packet);
// input a tcp segment
extern int input_tcp(const uint8_t* data, int len);



#endif  // TCP_H_

