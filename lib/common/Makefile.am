##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS = -fasynchronous-unwind-tables

AM_LDFLAGS = -rdynamic
AM_LDFLAGS += -ldl
AM_LDFLAGS += -ljansson
AM_LDFLAGS += -lrt
AM_LDFLAGS += -lev


noinst_LTLIBRARIES=libCcspWifiAgent_common.la

libCcspWifiAgent_common_la_SOURCES = os_time.c util.c monitor.c os.c os_util.c os_exec.c 

libCcspWifiAgent_common_la_CPPFLAGS = -I$(top_srcdir)/source/WifiSsp/lib/const -I$(top_srcdir)/source/WifiSsp/lib/ds -I$(top_srcdir)/source/WifiSsp/lib/inc -I$(top_srcdir)/source/WifiSsp/lib/json_util -I$(top_srcdir)/source/WifiSsp/lib/log -I$(top_srcdir)/source/WifiSsp/lib/osa -I$(top_srcdir)/source/WifiSsp/lib/ovsdb -I$(top_srcdir)/source/WifiSsp/lib/pjs -I$(top_srcdir)/source/WifiSsp/lib/qm -I$(top_srcdir)/source/WifiSsp/lib/schema -I$(top_srcdir)/source/WifiSsp/lib/datapipeline

libCcspWifiAgent_common_la_LDFLAGS = -rdynamic -ldl -ljansson -lrt -lev

