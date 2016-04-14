# Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

cmake_minimum_required (VERSION 2.8)

set (L2MACD hpe-l2macd)
project (${L2MACD})
set (SRC_DIR src)
set (INCL_DIR include)

# Define compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror")

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OVSDB REQUIRED libovsdb)

include_directories (${PROJECT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/${INCL_DIR}
                     ${OVSCOMMON_INCLUDE_DIRS}
)

# Source files to build l2macd
set (SOURCES ${SRC_DIR}/l2macd.c ${SRC_DIR}/l2macd_ovsdb_if.c)

# Rules to build l2macd
add_executable (${L2MACD} ${SOURCES})
target_link_libraries (${L2MACD} ${OVSCOMMON_LIBRARIES}
                       ${OVSDB_LIBRARIES}
                       -lpthread -lrt)

# Build ops-l2macd cli shared libraries.
add_subdirectory(src/cli)

# Rules to install l2macd binary in rootfs
install(TARGETS ${L2MACD}
    RUNTIME DESTINATION bin)
