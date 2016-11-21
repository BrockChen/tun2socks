// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: tcp_test.cc
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-17 09:33:24

#include "catch.hpp"
#include "../src/ip4.h"
#include "../src/tcp.h"
#include "test_data.h"

TEST_CASE("tcp", "parse") {
  struct ip_packet ip;
  init_data();
  REQUIRE(parse_ip(conn_syn, 100, &ip) == 0);

  struct tcp_segment tcp;
  REQUIRE(parse_tcp(&ip, ip.total_len-ip.ihl, &tcp) == 0);
  REQUIRE(tcp.sport == 58711);
  REQUIRE(tcp.dport == 80);
  REQUIRE(tcp.seq == 1680879434);
  REQUIRE(tcp.ack == 0);
  REQUIRE(tcp.dlen == 0);
  REQUIRE(tcp.len == 1);  // 因为syn,fin也可以算是内容的一部分
  REQUIRE(tcp.thl == 44);
  REQUIRE(tcp.win == 65535);
  REQUIRE(tcp.csum == 0x43ed);
  REQUIRE(tcp.urp == 0);
}
