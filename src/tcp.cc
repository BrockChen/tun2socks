// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: tcp.cc
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-16 23:17:15

#include "tcp.h"
#include <stdint.h>
#include <arpa/inet.h>
#include "errors.h"
#include "ip4.h"

int parse_tcp(struct ip_packet *ip, int len, struct tcp_segment* seg) {
  if (len < 20) {
    return ERR_HEADER_TOO_SHORT;
  }
  const struct tcp_hdr* h = reinterpret_cast<const struct tcp_hdr*>(ip->data);
  seg->sport = ntohs(h->sport);
  seg->dport = ntohs(h->dport);
  seg->seq = ntohl(h->seq);
  seg->ack = ntohl(h->ack_seq);
  seg->thl = (h->thl) << 2;
  seg->dlen = ip->total_len - ip->ihl - seg->thl;

  seg->len = seg->dlen + h->syn + h->fin;

  seg->win = ntohs(h->win);
  seg->csum = ntohs(h->csum);
  seg->urp = ntohs(h->urp);
  seg->prc = 0;
  seg->seq_last = seg->seq + seg->len - 1;
  return ERR_SUCCESS;
}


int input_tcp(const uint8_t* data, int len) {
  /*
  int ret = ERR_SUCCESS;
  struct tcp_segment tcp;
  if ((ret=parse_tcp(data, len, &tcp)) != ERR_SUCCESS) {
    return ret;
  }
  */
  return ERR_SUCCESS;
}
