################################################################
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
################################################################

#
# The root of of our repository is here:
#
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

#
# Initialize local submodules if necessary 
#
ifndef SUBMODULES

SUBMODULES := $(ROOT)/submodules

SUBMODULE_UPDATE_RESULT := $(shell python $(SUBMODULES)/init.py $(ROOT))

ifneq ($(lastword $(SUBMODULE_UPDATE_RESULT)),submodules:ok.)
$(info Local submodule update failed.)
$(info Result:)
$(info $(SUBMODULE_UPDATE_RESULT))
$(error Abort)
endif

endif

export SUBMODULES
export BUILDER := $(SUBMODULES)/infra/builder/unix










