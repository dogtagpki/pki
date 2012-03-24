#
# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#
#
# sql schema
#
CREATE TABLE requests ( type TEXT, ip TEXT, note TEXT, data TEXT, output TEXT, serialno TEXT, subject_dn TEXT,  meta_info TEXT, status TEXT, errorString TEXT, processed_by TEXT, assigned_to TEXT, updated_at TEXT, created_at TEXT, created_by TEXT )
CREATE TABLE users ( uid TEXT, name TEXT, password TEXT, email TEXT, certificate TEXT, created_at TEXT, created_by TEXT )
CREATE TABLE groups ( gid TEXT, name TEXT, created_at TEXT, created_by TEXT )
CREATE TABLE roles ( uid TEXT, gid TEXT )
CREATE TABLE pins ( key TEXT, pin TEXT, rid TEXT, created_at TEXT, created_by TEXT )
CREATE TABLE certificates ( rid TEXT, csr TEXT, subject_dn TEXT, certificate TEXT, serialno TEXT, approved_by TEXT, created_at TEXT )
#
# add defaults
#
INSERT INTO groups (gid, name) values ('administrators','Administrators');
INSERT INTO groups (gid, name) values ('agents','Agents');
