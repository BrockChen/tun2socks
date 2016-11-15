// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: ipv4_test.cc
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-15 10:37:45

#include "catch.hpp"
#include "../src/ip4.h"


extern uint8_t buf1[20];
extern uint8_t buf2[20];
extern uint8_t buf3[20];

TEST_CASE("IPV4", "ip parser") {
  struct ip_hdr *ip = reinterpret_cast<struct ip_hdr *>(buf1);
  REQUIRE(ip->version == 4);
  REQUIRE(ip->ihl >= 5);
  REQUIRE(ntohs(ip->len) == 328);
  REQUIRE(ntohs(ip->id) == 38941);
  uint16_t frag_off = ntohs(ip->frag_off);
  REQUIRE((frag_off & IP_DF) != IP_DF);
  frag_off &= IP_OFFMASK;
  REQUIRE(frag_off== 0);
  REQUIRE(ip->ttl == 255);
  REQUIRE(ip->protocol == 17);  // UDP
  REQUIRE(ntohs(ip->chk_sum) == 0x2288);
  REQUIRE(ntohl(ip->srcaddr) == 0);
  REQUIRE(ntohl(ip->dstaddr) == 0xffffffff);

  ip = reinterpret_cast<struct ip_hdr *>(buf2);
  REQUIRE(ip->version == 4);
  REQUIRE(ip->ihl >= 5);
  REQUIRE(ntohs(ip->len) == 393);
  REQUIRE(ntohs(ip->id) == 3436);
  
  frag_off = ntohs(ip->frag_off);
  REQUIRE((frag_off & IP_DF) == IP_DF);
  frag_off &= IP_OFFMASK;
  REQUIRE(frag_off== 0);

  REQUIRE(ip->ttl == 64);
  REQUIRE(ip->protocol == 6);  // TCP
  REQUIRE(ntohs(ip->chk_sum) == 0xd531);
  REQUIRE(ntohl(ip->srcaddr) == 0xc0a8c7f0);  // 192.168.199.240
  REQUIRE(ntohl(ip->dstaddr) == 0xb4a31995);  // 180.163.25.149
}
