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

#include "tun2socks/tcp.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tun2socks/errors.h"
#include "tun2socks/ip4.h"


std::map<std::string, struct tcp_pcb*> pcbs;


tcp_segment* parse_segment(const ip_packet *ip) {
  if (ip->total_len - ip->ihl < 20) {
    return NULL;
  }

  tcp_segment* seg = reinterpret_cast<tcp_segment*>(
      malloc(sizeof(tcp_segment)));
  struct tcp_hdr *h = reinterpret_cast<struct tcp_hdr*>(ip->data);
  seg->sport = ntohs(h->sport);
  seg->dport = ntohs(h->dport);
  seg->seq = ntohl(h->seq);
  seg->ack = ntohl(h->ack_seq);
  seg->thl = (h->thl) << 2;

  seg->flags = 0;
  if (h->fin == 1) {
    seg->flags |= TH_FIN;
  }
  if (h->syn == 1) {
    seg->flags |= TH_SYN;
  }
  if (h->rst == 1) {
    seg->flags |= TH_RST;
  }
  if (h->psh == 1) {
    seg->flags |= TH_PUSH;
  }
  if (h->ack == 1) {
    seg->flags |= TH_ACK;
  }
  if (h->urg == 1) {
    seg->flags |= TH_URG;
  }
  if (h->ece == 1) {
    seg->flags |= TH_ECE;
  }
  if (h->cwr == 1) {
    seg->flags |= TH_CWR;
  }

  seg->dlen = ip->total_len - ip->ihl - seg->thl;

  seg->len = seg->dlen + h->syn + h->fin;

  seg->win = ntohs(h->win);
  seg->csum = ntohs(h->csum);
  seg->up = ntohs(h->urp);
  seg->prc = 0;
  seg->seq_last = seg->seq + seg->len - 1;
  uint8_t* data = reinterpret_cast<uint8_t*>(malloc(sizeof(seg->dlen)));
  memcpy(data, ip->data+seg->thl, seg->dlen);
  seg->data = data;
  return seg;
}

void drop_tcp(struct tcp_segment *seg) {
  if (seg == NULL) {
    return;
  }
  if (seg->data != NULL) {
      free(seg->data);
      seg->data = NULL;
  }
  free(seg);
}

struct tcp_pcb* lookup_pcb(uint32_t srcip, uint16_t srcport,
                           uint32_t dstip, uint16_t dstPort) {
  char pcbkey[100] = {'\0'};
  snprintf(pcbkey, sizeof(pcbkey), "%d|%d|%d|%d", srcip, srcport,
           dstip, dstPort);
  std::string key(pcbkey);
  auto iter = pcbs.find(key);
  if (iter != pcbs.end()) {
    if (iter->second != NULL) {
      return iter->second;
    }
  }
  struct tcp_pcb* pcb = reinterpret_cast<struct tcp_pcb*>(malloc(
      sizeof(struct tcp_pcb)));
  pcbs[key] = pcb;
  pcb->state = TCP_LISTEN;
  pcb->srcaddr = srcip;
  pcb->dstaddr = dstip;
  pcb->sport = srcport;
  pcb->dport = dstPort;
  pcb->iss = generate_iss();
  pcb->recved_fin = 0;
  return pcb;
}

int generate_iss() {
  return 1525252;;
}
