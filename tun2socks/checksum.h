// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: checksum.h
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-14 15:01:43

#ifndef TUN2SOCKS_CHECKSUM_H_
#define TUN2SOCKS_CHECKSUM_H_

#include "ip4.h"  // NOLINT

int ip_checksum(const uint8_t * packets, int len);

#endif  // TUN2SOCKS_CHECKSUM_H_
