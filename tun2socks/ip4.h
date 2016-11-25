// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails and http://www.sailsxu.com/.
//
// Filename: ip4.h
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-11 22:41:37
//                    ip header for big Endian hosts
// 0-----+-------+-------------15-----------------------------31----
// | ver |  ihl  |      tos     |           len               |  ^
// +-----+-------+--------------+-----+-----------------------+  |
// |                            |flags|     flag_offset       |  |
// +-------------+--------------+-----+-----------------------+ 20 bytes
// |     ttl     | idprotocol   |                chk_sum      |  |
// +-------------+--------------+-----------------------------+  |
// |                         srcaddr                          |  |
// +----------------------------------------------------------+  |
// |                         dstaddr                          |  v
// +----------------------------------------------------------+ ----
// |                     options(if exist)                    |
// +----------------------------------------------------------+
// |                        payload                           |
// +----------------------------------------------------------+
//

#ifndef TUN2SOCKS_IP4_H_
#define TUN2SOCKS_IP4_H_


#include <stdint.h>
#include "tun2socks/define.h"

#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

#define IP_MORE_FRAGMENTS  1
#define IP_DNOT_FRAGMENT   2
#define IP_RESERVED_BIT    4

// Mac头部，总长度14字节
// struct eth_hdr {
//   uint8_t dstmac[6];  // 目标mac地址
//   uint8_t srcmac[6];  // 源mac地址
//   uint16_t eth_type;  // 以太网类型
// } __attribute__((packed));

// 一个完整的packet(可能会由多个ip包组成)
typedef struct ip_packet {
  uint8_t ihl;
  uint8_t version;
  uint8_t tos;
  uint16_t total_len;
  uint16_t id;
  uint8_t flags;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t chk_sum;           // 检验和
  uint32_t srcaddr;           // 源IP地址
  uint32_t dstaddr;           // 目的IP地址
  uint8_t *data;
} ip_packet;

// 0表示成功，1长度小于20，2表示不是ipv4类型，3：表示整个包不完整
int parse_header(const uint8_t* data, int len, ip_packet* packet);
ip_packet*  parse_ip(const uint8_t* data, int len);
int drop_ip(ip_packet* packet);

int ip_output(struct tcp_pcb *pcb, uint8_t* data, int len);

#endif  // TUN2SOCKS_IP4_H_
