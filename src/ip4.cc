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
#include <checksum.h>

struct ip_reassitem* reass_header = nullptr;

// 拼接，把完整的包交给上层处理
void ip_input(ip_hdr* ip) {
  // 这里只处理tcp
  if (ip->protocol != TCP_PROTOCOL) {
    return;
  }
  // 校验ip包合法性, 版本,checksum
  if (ip->version != 4) {
    DEBUG_LOG("IP packet dropped due to bad version number:%d", ip->version);
    return;
  }

  int checksum = ip_checksum(reinterpret_cast<uint8_t*>(ip), 20);
  if (checksum != ntohs(ip->chk_sum)) {
    DEBUG_LOG("IP packet dropped due to bad checksum:%d", ntohs(ip->chk_sum));
    return;
  }

  // 如果没有分片，那么就不用拼接
  int flag_offset = ntohl(ip->frag_off);
  if ((flag_offset & IP_MF) != IP_MF) {
    // 这里只处理tcp
    return;
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
}

void ip_output() {
}
