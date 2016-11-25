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

#include <arpa/inet.h>
#include "tun2socks/tcp_output.h"
#include "tun2socks/errors.h"
#include "tun2socks/tcp.h"


static void handle_listen(const tcp_segment* seg, tcp_pcb* pcb) {
  // wait syn
  if ((seg->flags & TH_SYN) == TH_SYN) {  // SYN
    // 发送ack+syn给另一方
    pcb->snd_nxt = pcb->seq + 1;
    if (tcp_send_synack(pcb) == ERR_SUCCESS) {
      pcb->state = TCP_SYN_RECEIVED;
    }
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
