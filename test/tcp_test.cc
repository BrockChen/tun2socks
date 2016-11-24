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
#include "tun2socks/ip4.h"
#include "tun2socks/tcp.h"
#include "test/test_data.h"
#include "tun2socks/checksum.h"


TEST_CASE("tcp", "parse") {
  init_data();
  ip_packet* ip = parse_ip(conn_syn, 100);
  
  REQUIRE(ip != NULL);

  tcp_segment* tcp = parse_segment(ip);
  REQUIRE(tcp != NULL);

  int csum = tcp_checksum(ip->data, ip->total_len - ip->ihl,
                          ip->srcaddr, ip->dstaddr);
  REQUIRE(csum == 0x3fa1);  // 由于这个是发出去的包，所以wireshark中显示的不一样
  drop_ip(ip);
  
  REQUIRE(tcp->sport == 58711);
  REQUIRE(tcp->dport == 80);
  REQUIRE(tcp->seq == 1680879434);
  REQUIRE(tcp->ack == 0);
  REQUIRE(tcp->dlen == 0);
  REQUIRE(tcp->len == 1);  // 因为syn,fin也可以算是内容的一部分
  REQUIRE(tcp->thl == 44);
  REQUIRE(tcp->win == 65535);
  REQUIRE(tcp->csum == 0x43ed);
  REQUIRE(tcp->up == 0);
  
  drop_tcp(tcp);


  ip = parse_ip(conn_syn_ack, 100);
  REQUIRE(ip != NULL);
  REQUIRE(ip->chk_sum == 0x4aae);
  int ipcheck = ip_checksum(conn_syn_ack, 20);
  REQUIRE(ipcheck == 0x4aae);
  int tcpsum = tcp_checksum(ip->data, ip->total_len - ip->ihl,
                          ip->srcaddr, ip->dstaddr);
  REQUIRE(tcpsum == 0x5ffb);
  drop_ip(ip);
}
