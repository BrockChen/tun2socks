// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: tcp_input.cc
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-24 00:23:52

#include "tun2socks/errors.h"
#include "tun2socks/tcp.h"
#include <arpa/inet.h>



static void handle_listen(const tcp_segment* seg, tcp_pcb* pcb) {
  // wait syn
  if ((seg->flags & TH_SYN) == TH_SYN) {

    // 发送ack+syn给另一方
    struct tcp_hdr h;
    h.sport = htons(seg->dport);
    h.dport = htons(seg->sport);
    h.seq = htonl(pcb->iss);
    h.ack_seq = htonl(seg->seq + seg->len);
    h.reserved = htonl(0);
    h.thl = 5;
    h.fin = 1;
    h.ack = 1;
    h.win = 65535;
    h.csum = 0;
    h.urp = htons(0);
  }
}



int tcp_in(const ip_packet *ip) {

  tcp_segment* seg = parse_segment(ip);
  if (seg == NULL) {
    return ERR_TCP_PARSE;
  }
  tcp_pcb* pcb = lookup_pcb(ip->srcaddr, seg->sport,
                            ip->dstaddr, seg->dport);

  switch (pcb->state) {
    case TCP_LISTEN: {
      handle_listen(seg, pcb);
      
      break;
    }
    default:
      break;
  }

  drop_tcp(seg);
  seg = NULL;
  return ERR_SUCCESS;
}
