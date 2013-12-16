#################################################################
#
#        Copyright 2013, Big Switch Networks, Inc.
#
# Licensed under the Eclipse Public License, Version 1.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#        http://www.eclipse.org/legal/epl-v10.html
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the
# License.
#
#################################################################
include ../../init.mk

MODULE := indigo-lri
include $(BUILDER)/standardinit.mk


LIBRARY := lri_main
$(LIBRARY)_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/lib.mk

DEPENDMODULES := SocketManager OFConnectionManager PortManager \
	OS Forwarding OFStateManager Configuration IOF murmur \
	loci indigo VPI PPE FME BigHash BigList cjson AIM


include $(BUILDER)/dependmodules.mk

BINARY := lri

$(BINARY)_LIBRARIES := $(LIBRARY_TARGETS)
include $(BUILDER)/bin.mk


include $(BUILDER)/targets.mk

# These indicate Linux specific implementations to be used for
# various features
GLOBAL_CFLAGS += -DINDIGO_LINUX_LOGGING
GLOBAL_CFLAGS += -DINDIGO_LINUX_TIME
GLOBAL_CFLAGS += -DINDIGO_FAULT_ON_ASSERT
GLOBAL_CFLAGS += -DINDIGO_MEM_STDLIB
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DPORTMANAGER_CONFIG_INCLUDE_VPI_PCAPDUMP=1

GLOBAL_CFLAGS += -DOF_OBJECT_TRACKING
GLOBAL_CFLAGS += -g

ifdef LRI_DEBUG_LEVEL
GLOBAL_CFLAGS += -DLRI_DEBUG_LEVEL=${LRI_DEBUG_LEVEL}
endif

ifdef OF_CXN_DUMP_ALL_OBJECTS
GLOBAL_CFLAGS += -DOF_CXN_DUMP_ALL_OBJECTS
endif

GLOBAL_LINK_LIBS += -lpthread -lpcap -ledit -lm
