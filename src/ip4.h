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

#ifndef IP4_H_
#define IP4_H_

#include <stdint.h>
#include "define.h"  // NOLINT

#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

// Mac头部，总长度14字节
struct eth_hdr {
  uint8_t dstmac[6];  // 目标mac地址
  uint8_t srcmac[6];  // 源mac地址
  uint16_t eth_type;  // 以太网类型
} __attribute__((packed));

// IP头部，总长度20字节, 这里是小端结构
struct ip_hdr {
  uint8_t ihl : 4;            // 首部长度
  uint8_t version : 4;        // 版本
  uint8_t tos;                // 服务类型
  uint16_t len;               // 总长度
  uint16_t id;                // 标识
  uint16_t frag_off;          // 3 bits flags and 13 bits fragment-offset
#define IP_RF 0x8000          // reserved fragment flag
#define IP_DF 0x4000          // dont fragment flag
#define IP_MF 0x2000          // more fragments flag
#define IP_OFFMASK 0x1fff     // mask for fragmenting bits
  uint8_t  ttl;               // 生存时间
  uint8_t  protocol;          // 协议
  uint16_t chk_sum;           // 检验和
  uint32_t srcaddr;           // 源IP地址
  uint32_t dstaddr;           // 目的IP地址
} __attribute__((packed));


extern struct ip_reassitem* reass_header;
extern void ip_input(ip_hdr* ip);

// 用于ip数据拼接的链
struct ip_reassitem {
  struct ip_reassitem* next;
  struct ip_reassdata* data;
  uint16_t id;                // 如果ip分片，那么不同片中id会相同
  uint32_t srcaddr;           // 源IP地址
  uint32_t dstaddr;           // 目的IP地址
  uint16_t data_len;          // 已经收到的数据报长度
  uint8_t flags;              // 是否收到最后一个分片包
  uint8_t timer;              // 设置超时间隔
};

// 用于ip数据拼接的项
struct ip_reassdata {
  struct ip_reassdata *next;  // 用于构建单向链表的指针
  struct ip_hdr iphdr;        // 该数据报的 IP 报头
};





#endif  // IP4_H_
