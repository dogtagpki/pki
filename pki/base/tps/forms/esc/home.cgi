#!/usr/bin/perl
#
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
#
#
#
print "Content-type: text/xml\n\n";
print "<\?xml version=\"1.0\" encoding=\"UTF-8\"\?>";
print "<ServiceInfo>";
print "<IssuerName>";
print "Fedora Project";   # Vendor
print "</IssuerName>\n";
print "<Services>";
print "<Operation>";
print "http://machine.fedora.redhat.com:7888/nk_service";
print "</Operation>";
print "<UI>";
print "http://machine.fedora.redhat.com:7888/cgi-bin/esc.cgi";
print "</UI>";
print "</Services>";
print "</ServiceInfo>";
