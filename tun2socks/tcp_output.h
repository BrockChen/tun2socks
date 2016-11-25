// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: tcp_output.h
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-25 09:34:25

#ifndef TUN2SOCKS_TCP_OUTPUT_H_
#define TUN2SOCKS_TCP_OUTPUT_H_

#include "tun2socks/tcp.h"


int tcp_send_syn(struct tcp_pcb *pcb);

int tcp_send_synack(struct tcp_pcb *pcb);

int tcp_send_finack(struct tcp_pcb *pcb);

int tcp_send_finack(struct tcp_pcb *pcb);

int tcp_send_fin(struct tcp_pcb *pcb);

int tcp_send_finack(struct tcp_pcb *pcb);





#endif  // TUN2SOCKS_TCP_OUTPUT_H_
