# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301  USA 
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#
Overview
========

tpsclient is a test utility that talks to the TPS
directly using HTTP protocol.

It is a software-based token. It can be used as a driver
for stress/scalability testing.

It can be used for the following operations:

  enrollment     - This is for getting a certificate
                   into the token.
  pin reset      - This is for changing the token's pin. 
  format         - This is for formatting the token to 
                   remove the certificates from the token
                   and load fresh applets.

Configuration
=============

The tpsclient utility accepts a test script file. Each script 
file contains a sequence of operations. Each operation 
is composed of a set of name value pairs. For example,

  op=var_set name=ra_host value=familiar

It starts with an operation type such as 'op=var_set' and
follows by a list of parameters as 'name=ra_host value=familiar'.

The currently supported operation types are as follows:

  op=var_list         - list all TPS connection parameters
  op=var_get          - retrieve the value of a TPS connection parameter
  op=var_set          - set the value of a TPS conection parameter

  op=exit             - exit this utility
  op=help             - get more information about each operation

  op=token_status     - list all token parameters
  op=token_set        - set the value of a token parameter

  op=ra_enroll        - perform an enrollment operation
  op=ra_reset_pin     - perform a pin reset operation
  op=ra_format        - perform a format operation

Configuration Examples
======================

Setup TPS's connection information:

  op=var_set name=ra_host value=familiar
  op=var_set name=ra_port value=9003
  op=var_set name=ra_uri value=/nk_service

Setup token's ID, Applet ID, and Key Set Version:

  op=token_set cuid=a00192030405060708c9 app_ver=6FBBC105 key_info=0101

Setup Key Data: (Note that '404142434445464748494a4b4c4d4e4f' is the
default key created by the manufacturer in the real token)

  op=token_set auth_key=404142434445464748494a4b4c4d4e4f
  op=token_set mac_key=404142434445464748494a4b4c4d4e4f
  op=token_set kek_key=404142434445464748494a4b4c4d4e4f

Perform an enrollment operation:

  op=ra_enroll uid=sectest13 pwd=home-boy new_pin=password

Perform a pin reset operation:

  op=ra_reset_pin uid=test pwd=password new_pin=newpassw

Perform a format operation:

  op=ra_format uid=test pwd=password new_pin=newpassw

Print the information inside token:

  op=token_status

Applet Upgrade Example 
======================

To test applet upgrade, you should first setup TPS to enable
applet upgrade. Please consult the TPS documentation for those
details.

You should try to do an enrollment operation with an applet
version that's different from the one that's configured in
the TPS's configuration file. For example, you should have 
the following in the test script.

    op=token_set cuid=18888883333300000004 app_ver=402428AD key_info=0101

This indicates that the token's applet version is currently at 
40248AD. 


After execution, you should see an audit event logged on the
TPS's audit log file like this,


    ...
    [2004-11-15 16:56:38] 847f220 Enrollment - op='applet_upgrade'
    app_ver='0.0.402428AD' new_app_ver='1.2.416DA155'
    ...
    ...
    [2004-11-15 16:56:43] 847f220 Enrollment - status='success'
    app_ver='1.2.416DA155' key_ver='0101' cuid='18888883333300000004'
    msn='00000000' uid='user1' auth='ldap1' time='7243 msec'

Key Change Over Example
=======================

To test key change over, you should setup a version 2 master key
in TKS and enable the key change over feature in TPS. Please
consult the TPS documentation for details.

You should try to do an enrollment with a version 1 key in the
token. TPS should change the key in your token to 
version 2. For example, you should have the following in 
the test script:

  op=token_set cuid=a00192030405060708c9 app_ver=6FBBC105 key_info=0101
  op=token_set auth_key=404142434445464748494a4b4c4d4e4f
  op=token_set mac_key=404142434445464748494a4b4c4d4e4f
  op=token_set kek_key=404142434445464748494a4b4c4d4e4f

Note 'key_info=0101' indicates a version 1 key set.

After the execution, you should see the following in the output:

  ...
  Output> cuid : 'a00192030405060708c9' (10 bytes)
  Output> key_info : '0201' (2 bytes)
  Output> auth_key : 'a3523ec8c0740b621e18e9cdd99f75fc' (16 bytes)
  Output> mac_key : '903af964eb7ede26ea189243a5caad9c' (16 bytes)
  Output> kek_key : '44ef9de3775121a871c152563d9b9860' (16 bytes)
  ...

'key_info: 0201' indicates that the current key set in the
token now changed from '0101' to '0201'. And as you noticed, 
the key data for auth, mac, and kek keys are all different.

If you check the TPS's log, you should see an audit event for
the key change over operation. 

After this, you should try to enroll with a version 2 keys.
For example, create a new test script that contains:

  op=token_set cuid=a00192030405060708c9 app_ver=6FBBC105 key_info=0201
  op=token_set auth_key=a3523ec8c0740b621e18e9cdd99f75fc
  op=token_set mac_key=903af964eb7ede26ea189243a5caad9c
  op=token_set kek_key=44ef9de3775121a871c152563d9b9860

Execute this test script, and you should NOT see an audit
event for key change over. It is because your token already
has a version 2 key set.

You can also try to key change over from version 2 back to 
version 1 with appropriate TPS configuration and test 
script.

Choose a specific profile in TPS
================================

TPS can be configured to support several profiles like 

  1) devicekey profile  - used to issue only signing certs
  2) userKey profile - used to issue signing and encryption certs

the tpsclient can be configured to tell TPS to select the right
profile by adding the following to the op=ra_enroll line in the
test script
  
  op=ra_enroll uid=user1 num_threads=1 pwd=password new_pin=newpassw
  extensions=tokenType=userKey

  (OR)
 
  op=ra_enroll uid=user1 num_threads=1 pwd=password new_pin=newpassw
  extensions=tokenType=deviceKey

Stress test Example
===================

tpsclient can be configured to start multiple threads to perform
enrollment or pin reset or format operations, to stress the TPS
installation.

  op=ra_enroll uid=user1 num_threads=1 pwd=password new_pin=newpassw
  extensions=tokenType=userKey

In the above test script line, the num_threads parameter indicates
the number of threads that will be started. 

Also , to control the number of operations being performed, the
following parameter should be set in the test script line.

  op=ra_enroll uid=user1 num_threads=1 pwd=password new_pin=newpassw
  extensions=tokenType=userKey max_ops=10

max_ops, indicates the number of operations that will be performed
by all the threads.




Execution
=========

For Enrollment Operation:

  tpsclient < enroll.test

For Reset Pin Operation:

  tpsclient < reset_pin.test

Note
====

You may need to setup LD_LIBRARY_PATH (On Linux, and Solaris) to 
point to the directory where you have NSPR, NSS, TPS shared libraries.

