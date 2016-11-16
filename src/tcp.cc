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

#ifndef TCP_H_
#define TCP_H_

#include "tcp.h"
#include <stdint.h>
#include "errors.h"

int parse_tcp(const uint8_t* data, int len) {
}


int input_tcp(const uint8_t* data, int len) {
  return ERR_SUCCESS;
}

#endif  // TCP_H_
