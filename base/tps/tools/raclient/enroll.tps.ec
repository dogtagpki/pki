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
########################################################
# Description:
#    This data file tests enrollment operation.
#
# Execution:
#    tpsclient < enroll.test
#
########################################################
op=var_set name=ra_host value=host1
op=var_set name=ra_port value=7891
op=var_set name=ra_uri value=/nk_service
# print original token status
op=token_set cuid=a00192030405060708c9 msn=01020304 app_ver=6FBBC105 key_info=0101 major_ver=0 minor_ver=0
op=token_set auth_key=404142434445464748494a4b4c4d4e4f
op=token_set mac_key=404142434445464748494a4b4c4d4e4f
op=token_set kek_key=404142434445464748494a4b4c4d4e4f
op=token_status
# slotnamefile is the file name which contains the name of the token
op=ra_enroll uid=pinmanager num_threads=1 pwd=netscape new_pin=netscape extensions=tokenType=userKey keygen=true slotnamefile=tokenname tokpasswd=redhat
# print changed token status
op=token_status
op=exit

