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

// 拼接
void ip_input(ip_hdr* ip) {
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
  

  // 寻找reassitem
  if (reass_header == nullptr) {
    ip_reassitem* item = (reinterpret_cast<ip_reassitem*>(
        malloc(sizeof(ip_reassitem))));
    item->next = nullptr;
    item->data = (reinterpret_cast<ip_reassdata*>(
        malloc(sizeof(ip_reassdata))));
    item->srcaddr = ip->srcaddr;
    item->dstaddr = ip->dstaddr;
    item->data_len = ip->len-ip->ihl;

    reass_header = item;
  } else {
  }
}

void ip_output() {
}
