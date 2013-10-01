#!/usr/bin/python 
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

################################################################
#
# This script updates all local submodules if they haven't
# been initialized. 
#
################################################################
import os
import sys
import subprocess

# Move to the root of the repository
root = sys.argv[1]
os.chdir(root)

submodule_status = {}
try:
    for entry in subprocess.check_output(['git', 'submodule', 'status']).split("\n"):
        data = entry.split()
        if len(data) >= 2:
            submodule_status[data[1].replace("submodules/", "")] = data[0]
except Exception as e:
    print repr(e)
    raise

for (module, status) in submodule_status.iteritems():
    if status[0] == '-':
        # This submodule has not yet been updated
        print "Updating %s" % module
        if subprocess.check_call(['git', 'submodule', 'update', '--init', '--recursive', 'submodules/%s' % module]) != 0:
            print "git error updating module '%s'." % (module, switchlight_root, module)
            sys.exit(1)

print
print "submodules:ok."



