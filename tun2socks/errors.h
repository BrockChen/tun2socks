// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: errors.h
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-16 22:59:36

#ifndef TUN2SOCKS_ERRORS_H_
#define TUN2SOCKS_ERRORS_H_

#define ERR_SUCCESS            0
#define ERR_HEADER_TOO_SHORT   1
#define ERR_PACKET_TOO_SHORT   2
#define ERR_IP_VERSION         3
#define ERR_NOT_TCP_PACKET     4
#define ERR_CHECKSUM           5
#define ERR_TTL                6
#define ERR_IP_NEED_REASSEMBLE 7
#define ERR_IP                 8
#define ERR_TCP_PARSE          9


#define ERR_OTHER            1000

#endif  // TUN2SOCKS_ERRORS_H_
