// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: tcp_output.cc
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-24 22:53:37

#include <stdlib.h>
#include <arpa/inet.h>
#include "tun2socks/tcp.h"
#include "tun2socks/ip4.h"
#include "tun2socks/checksum.h"
#include "tun2socks/errors.h"

int tcp_transmit(tcp_hdr* thdr, struct tcp_pcb *pcb) {
  thdr->sport = pcb->sport;
  thdr->dport = pcb->dport;
  thdr->seq = pcb->seq;
  thdr->ack_seq = pcb->rcv_nxt;
  thdr->thl = 5;
  thdr->reserved = 0;
  thdr->win = pcb->rcv_wnd;
  thdr->csum = 0;
  thdr->urp = 0;

  thdr->sport = htons(thdr->sport);
  thdr->dport = htons(thdr->dport);
  thdr->seq = htonl(thdr->seq);
  thdr->ack_seq = htonl(thdr->ack_seq);
  thdr->win = htons(thdr->win);
  thdr->csum = htons(thdr->csum);
  thdr->urp = htons(thdr->urp);

  // 由于pcb->snd_nxt-pcb->seq表示数据长度，但是由于算上了h->syn + h->fin
  // 而它是在header中，所以要减去才是占用的实际长度
  int total_len = sizeof(tcp_hdr)+ (pcb->snd_nxt-pcb->seq) -
                  (thdr->syn + thdr->fin);

  thdr->csum = tcp_checksum(reinterpret_cast<uint8_t*>(thdr), total_len,
                            pcb->srcaddr, pcb->dstaddr);

  return ip_output(pcb, reinterpret_cast<uint8_t*>(thdr), total_len);
}


// 发送之前，要根据内容修改snd_nxt，因为发送时要根据snd_nxt和seq来计算tcp的数据
// 有多大，不然只是从tcp_hdr中没有办法得知
// 发送之后，要把pcb的状态更改
int tcp_send_syn(struct tcp_pcb *pcb) {
  if (pcb->state != TCP_CLOSE && pcb->state != TCP_LISTEN) {
    DEBUG_LOG("pcb was not in correct state (closed or listen)");
    return 1;
  }

  tcp_hdr* tcp = reinterpret_cast<tcp_hdr*>(malloc(sizeof(tcp_hdr)));
  memset(tcp, 0, sizeof(tcp_hdr));

  tcp->syn = 1;
  pcb->snd_nxt = pcb->seq+1;  // 内容只有一个字节

  int ret = ERR_SUCCESS;
  if ((ret = tcp_transmit(tcp, pcb)) != ERR_SUCCESS) {
    pcb->state = TCP_SYN_SENT;
  }
  
  return ret;
}

int tcp_send_synack(struct tcp_pcb *pcb) {
  tcp_hdr* tcp = reinterpret_cast<tcp_hdr*>(malloc(sizeof(tcp_hdr)));
  memset(tcp, 0, sizeof(tcp_hdr));

  tcp->syn = 1;
  tcp->ack = 1;

  pcb->snd_nxt = pcb->seq+1;  // 内容只有一个字节


  int ret = ERR_SUCCESS;
  if ((ret = tcp_transmit(tcp, pcb)) != ERR_SUCCESS) {
    pcb->state = TCP_SYN_RECEIVED;
  }
  

  return ret;
}

// send ack之后的状态要根据实际情况来
int tcp_send_ack(struct tcp_pcb *pcb) {
  if (pcb->state == TCP_CLOSE) return 0;

  tcp_hdr* tcp = reinterpret_cast<tcp_hdr*>(malloc(sizeof(tcp_hdr)));
  memset(tcp, 0, sizeof(tcp_hdr));

  tcp->ack = 1;

  int ret = ERR_SUCCESS;
  if ((ret = tcp_transmit(tcp, pcb)) != ERR_SUCCESS) {
    if (pcb->state == TCP_SYN_SENT) {  // 主动连接阶段
      pcb->state = TCP_ESTABLISHED;
    }

    // 正常数据的ack不处理
    // 被动关闭，收到fin之后的回复
    if (pcb->state == TCP_ESTABLISHED && pcb->recved_fin == 1) {
      pcb->state = TCP_CLOSE_WAIT;
    }
    
    if (pcb->state == TCP_FIN_WAIT_2) {  // 主动断开阶段
      pcb->state = TCP_TIME_WAIT;  // 等两个MSL后关闭
    }
  }
  
  return ret;
}


int tcp_send_fin(struct tcp_pcb *pcb) {
  tcp_hdr* tcp = reinterpret_cast<tcp_hdr*>(malloc(sizeof(tcp_hdr)));
  memset(tcp, 0, sizeof(tcp_hdr));

  tcp->fin = 1;
  pcb->snd_nxt = pcb->seq+1;

  int ret = ERR_SUCCESS;
  if ((ret = tcp_transmit(tcp, pcb)) != ERR_SUCCESS) {
    pcb->state = TCP_FIN_WAIT_1;
  }

  return ret;
}

int tcp_send_finack(struct tcp_pcb *pcb) {
  tcp_hdr* tcp = reinterpret_cast<tcp_hdr*>(malloc(sizeof(tcp_hdr)));
  memset(tcp, 0, sizeof(tcp_hdr));

  tcp->fin = 1;
  tcp->ack = 1;
  pcb->snd_nxt = pcb->seq+1;

  int ret = ERR_SUCCESS;
  if ((ret = tcp_transmit(tcp, pcb)) != ERR_SUCCESS) {
    pcb->state = TCP_LAST_ACK;
  }
  return ret;
}


int tcp_send_data(struct tcp_pcb *pcb, uint8_t* data, int len) {
  tcp_hdr* tcp = reinterpret_cast<tcp_hdr*>(malloc(sizeof(tcp_hdr)+len));
  memset(tcp, 0, sizeof(tcp_hdr));
  memcpy(tcp+sizeof(tcp_hdr), data, len);

  tcp->ack = 1;
  pcb->snd_nxt = pcb->seq + len;

  int ret = ERR_SUCCESS;
  if ((ret = tcp_transmit(tcp, pcb)) != ERR_SUCCESS) {
    pcb->state = TCP_LAST_ACK;
  }
  return ret;
}

