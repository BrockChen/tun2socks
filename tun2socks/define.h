// Copyright (C) 2016 sails Authors.
// All rights reserved.
//
// Official git repository and contact information can be found at
// https://github.com/sails/ and http://www.sailsxu.com/.
//
// Filename: define.h
//
// Author: sailsxu <sailsxu@gmail.com>
// Created: 2016-11-12 15:38:44

#ifndef TUN2SOCKS_DEFINE_H_
#define TUN2SOCKS_DEFINE_H_

#include <stdio.h>

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN (1)  // BYTE ORDER
#endif

#ifndef DEBUG_LOG
#define DEBUG_LOG(...) { \
    printf(__VA_ARGS__);    \
  }
#endif

#ifndef INFO_LOG
#define INFO_LOG(...) { \
    printf(__VA_ARGS__);   \
  }
#endif

#ifndef WARN_LOG
#define WARN_LOG(...) { \
    printf(__VA_ARGS__);   \
  }
#endif

#ifndef ERROR_LOG
#define ERROR_LOG(...) { \
    printf(__VA_ARGS__);    \
  }
#endif

#endif  // TUN2SOCKS_DEFINE_H_
