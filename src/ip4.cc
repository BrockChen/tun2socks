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

#include "ip4.h"  // NOLINT
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "checksum.h"
#include "errors.h"


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
  // 这里只处理tcp
  if (packet.protocol != TCP_PROTOCOL) {
    return ERR_NOT_TCP_PACKET;
  }
  // 校验ip包合法性, 版本,checksum
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
  if ((packet.flags & IP_MORE_FRAGMENTS) != IP_MORE_FRAGMENTS) {
    // 由于只处理tcp，tcp分段机制保证了ip层不用再分片
    return input_tcp(packet.data, packet.total_len-packet.ihl);
  }

  // 对于TCP来说，它是尽量避免分片的,它通过MSS（最长报文大小），用来表
  // 示本段所能接收的最大长度的报文段。MSS=MTU-TCP首部大小-IP首部大小，
  // MTU值通过查询链路层得知，常见以太网的MTU为1500。由于tcp的可选字段，
  // 会让tcp的头部最大为60字节，所以正常的最大段长度小于1460

  // 所以这时暂时不处理

  // // 寻找reassitem
  // if (reass_header == nullptr) {
  //   ip_reassitem* item = (reinterpret_cast<ip_reassitem*>(
  //       malloc(sizeof(ip_reassitem))));
  //   item->next = nullptr;
  //   item->data = (reinterpret_cast<ip_reassdata*>(
  //       malloc(sizeof(ip_reassdata))));
  //   item->id = ntohs(ip->id);
  //   item->srcaddr = ntohl(ip->srcaddr);
  //   item->dstaddr = ntohl(ip->dstaddr);
  //   item->data_len = ntohs(ip->len)-ip->ihl*4;

  //   reass_header = item;
  // } else {
  // }
  return ERR_OTHER;
}

void ip_output() {
}
