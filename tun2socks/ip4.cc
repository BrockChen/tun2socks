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

int parse_ip(const uint8_t* data, int len, ip_packet* packet) {
  if (len < 20) {
    return ERR_HEADER_TOO_SHORT;
  }
  const struct ip_hdr* header = reinterpret_cast<const struct ip_hdr*>(data);
  int total_len = ntohs(header->len);
  if (total_len > len) {  // 说明data不是一个完整的ip包
    return ERR_PACKET_TOO_SHORT;
  }
  int ret = ERR_SUCCESS;
  if ((ret = parse_header(data, len, packet)) != 0) {
    return ret;
  }

  // copy一份而不是指向原来的data中，因为对于有些ip包要多个包重组之后才能传给下层
  // 如果不在这里copy一份，就会导致可能会由于用户删除了data而导致出错；
  // 同理，对于tcp中解析也会存在这样的原因，导致在tcp解析中也要把tcp的内容copy
  // 一份，所以一个ip包在解析时，基本上会被copy两份
  uint8_t* content = reinterpret_cast<uint8_t*>(malloc(
      total_len - packet->ihl));
  memcpy(content, (data+packet->ihl), total_len - packet->ihl);
  packet->data = content;
  return ret;
}

extern int input_tcp(const uint8_t* data, int len);

// 拼接，把完整的包交给上层处理
int ip_input(const uint8_t* data, int len) {
  struct ip_packet packet;
  int ret = ERR_SUCCESS;
  if ((ret = parse_ip(data, len, &packet)) != 0) {
    return ret;
  }

  if (packet.ttl == 0) {
    DEBUG_LOG("IP Packet dropped due to ttl == 0");
    return ERR_TTL;
  }

  if (packet.version != 4) {
    DEBUG_LOG("IP packet dropped due to bad version number:%d", packet.version);
    return ERR_IP_VERSION;
  }

  int checksum = ip_checksum(data, len);
  if (checksum != packet.chk_sum) {
    DEBUG_LOG("IP packet dropped due to bad checksum:%d", packet.chk_sum);
    return ERR_CHECKSUM;
  }

  // 如果没有分片，那么就不用拼接
  if ((packet.flags & IP_MORE_FRAGMENTS) == IP_MORE_FRAGMENTS) {
    // 由于只处理tcp，tcp分段机制保证了ip层不用再分片
    DEBUG_LOG("IP packet dropped due to need reassemble");
    return ERR_IP_NEED_REASSEMBLE;
  }

  switch (packet.protocol) {
    case TCP_PROTOCOL:
      return input_tcp(packet.data, packet.total_len-packet.ihl);
      break;
    default:
      DEBUG_LOG("Unknown IP header proto\n");
      return ERR_NOT_TCP_PACKET;
      break;
  }

  return ERR_OTHER;
}

void ip_output() {
}
