// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: ip4.cc
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-11 23:53:41

#include "tun2socks/ip4.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "tun2socks/checksum.h"
#include "tun2socks/errors.h"
#include "tun2socks/tcp.h"


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

int parse_header(const uint8_t* data, int len, ip_packet* packet) {
  if (len < 20) {
    return ERR_HEADER_TOO_SHORT;
  }
  const struct ip_hdr* header = reinterpret_cast<const struct ip_hdr*>(data);
  if (header->version != 4) {
    return ERR_IP_VERSION;
  }
  packet->version = header->version;
  packet->ihl = header->ihl << 2;
  packet->total_len = ntohs(header->len);
  packet->id = ntohs(header->id);
  uint16_t frag_off = ntohs(header->frag_off);
  packet->flags = 0;
  if ((frag_off & IP_RF) == IP_RF) {
    packet->flags |= 0x04;
  }
  if ((frag_off & IP_DF) == IP_DF) {
    packet->flags |= 0x02;
  }
  if ((frag_off & IP_MF) == IP_MF) {
    packet->flags |= 0x01;
  }
  packet->frag_off = (frag_off &= IP_OFFMASK);
  packet->ttl = header->ttl;
  packet->protocol = header->protocol;
  packet->chk_sum = ntohs(header->chk_sum);
  packet->srcaddr = ntohl(header->srcaddr);
  packet->dstaddr = ntohl(header->dstaddr);
  return ERR_SUCCESS;
}

ip_packet*  parse_ip(const uint8_t* data, int len) {
  if (len < 20) {
    return NULL;
  }
  const struct ip_hdr* header = reinterpret_cast<const struct ip_hdr*>(data);
  int total_len = ntohs(header->len);
  if (total_len > len) {  // 说明data不是一个完整的ip包
    return NULL;
  }
  ip_packet* packet = reinterpret_cast<ip_packet*>(malloc(sizeof(ip_packet)));
  if (parse_header(data, len, packet) != 0) {
    free(packet);
    return NULL;
  }

  // copy一份而不是指向原来的data中，因为对于有些ip包要多个包重组之后才能传给下层
  // 如果不在这里copy一份，就会导致可能会由于用户删除了data而导致出错；
  // 同理，对于tcp中解析也会存在这样的原因，导致在tcp解析中也要把tcp的内容copy
  // 一份，所以一个ip包在解析时，基本上会被copy两份
  uint8_t* content = reinterpret_cast<uint8_t*>(malloc(
      total_len - packet->ihl));
  memcpy(content, (data+packet->ihl), total_len - packet->ihl);
  packet->data = content;
  return packet;
}

int drop_ip(ip_packet* packet) {
  if (packet != NULL) {
    if (packet->data != NULL) {
      free(packet->data);
      packet->data = NULL;
    }
    free(packet);
  }
  return 0;
}


// 拼接，把完整的包交给上层处理
int ip_input(const uint8_t* data, int len) {
  int ret = ERR_SUCCESS;
  ip_packet* packet = NULL;
  if ((packet = parse_ip(data, len)) == NULL) {
    return ERR_IP;
  }

  if (packet->ttl == 0) {
    DEBUG_LOG("IP Packet dropped due to ttl == 0");
    return ERR_TTL;
  }

  if (packet->version != 4) {
    DEBUG_LOG("IP packet dropped due to bad version number:%d",
              packet->version);
    return ERR_IP_VERSION;
  }

  int checksum = ip_checksum(data, len);
  if (checksum != packet->chk_sum) {
    DEBUG_LOG("IP packet dropped due to bad checksum:%d", packet->chk_sum);
    return ERR_CHECKSUM;
  }

  // 如果没有分片，那么就不用拼接
  if ((packet->flags & IP_MORE_FRAGMENTS) == IP_MORE_FRAGMENTS) {
    // 由于只处理tcp，tcp分段机制保证了ip层不用再分片
    DEBUG_LOG("IP packet dropped due to need reassemble");
    return ERR_IP_NEED_REASSEMBLE;
  }

  switch (packet->protocol) {
    case TCP_PROTOCOL:
      ret = tcp_in(packet);
      drop_ip(packet);
      return ret;
      break;
    default:
      DEBUG_LOG("Unknown IP header proto\n");
      return ERR_NOT_TCP_PACKET;
      break;
  }

  return ERR_OTHER;
}

void ip_output();
