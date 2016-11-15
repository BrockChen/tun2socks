cmake_minimum_required(VERSION 2.8.8)

project (tun2socks)
include_directories(src ../)

# 总的设置，让它生成到执行cmake的目录中
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -W -Wall -fPIC")

AUX_SOURCE_DIRECTORY(src SRCLIST)

ADD_LIBRARY(tun2socks ${SRCLIST})


AUX_SOURCE_DIRECTORY(test TESTLIST)
ADD_EXECUTABLE(testproj ${TESTLIST})
target_link_libraries(testproj tun2socks)
