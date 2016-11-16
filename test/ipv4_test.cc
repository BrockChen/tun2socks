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
#include "test_data.h"


extern uint8_t buf1[20];
extern uint8_t buf2[20];
extern uint8_t buf3[20];

TEST_CASE("IPV4", "ip parser") {

  struct ip_packet packet;
  REQUIRE(parse_header(buf1, 20, &packet) == 0);
  
  REQUIRE(packet.version == 4);
  REQUIRE(packet.ihl == 20);
  REQUIRE(packet.total_len == 328);
  REQUIRE(packet.id == 38941);
  REQUIRE(packet.frag_off == 0);
  REQUIRE(packet.flags == 0);
  REQUIRE(packet.ttl == 255);
  REQUIRE(packet.protocol == UDP_PROTOCOL);
  REQUIRE(packet.chk_sum == 0x2288);
  REQUIRE(packet.srcaddr == 0);
  REQUIRE(packet.dstaddr == 0xffffffff);


  REQUIRE(parse_header(buf2, 20, &packet) == 0);

  REQUIRE(packet.version == 4);
  REQUIRE(packet.ihl == 20);
  REQUIRE(packet.total_len == 393);
  REQUIRE(packet.id == 3436);
  REQUIRE(packet.flags == 0x02);
  REQUIRE(packet.frag_off == 0);
  REQUIRE(packet.ttl == 64);
  REQUIRE(packet.protocol == TCP_PROTOCOL);
  REQUIRE(packet.chk_sum == 0xd531);
  REQUIRE(packet.srcaddr == 0xc0a8c7f0);  // 192.168.199.240
  REQUIRE(packet.dstaddr == 0xb4a31995);  // 180.163.25.149


  init_data();
  REQUIRE(parse_ip(conn_syn, 100, &packet) == 0);
  REQUIRE(packet.version == 4);
  REQUIRE(packet.ihl == 20);
  REQUIRE(packet.total_len == 64);
  REQUIRE(packet.id == 0xb64f);
  REQUIRE(packet.flags == 0x02);
  REQUIRE(packet.frag_off == 0);
  REQUIRE(packet.ttl == 64);
  REQUIRE(packet.protocol == TCP_PROTOCOL);
  REQUIRE(packet.chk_sum == 0x0000);
  REQUIRE(packet.srcaddr == 0xc0a801bb);  // 192.168.1.187
  REQUIRE(packet.dstaddr == 0x6e4c130b);  // 110.76.19.11

}
