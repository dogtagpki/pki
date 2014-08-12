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

use LWP::UserAgent;

my $cfg = "../../conf/CS.cfg";
my $cahostport = `grep conn.ca1.hostport $cfg | cut -c19-`;

chomp($cahostport);

my $url = "https://$cahostport/ca/ee/ca/getCAChain?op=download&mimeType=application/x-x509-ca-cert";

my $agent = LWP::UserAgent->new;
$agent->timeout(30);

my $request = HTTP::Request->new('GET', $url);
my $response = $agent->request($request);

if ($response->is_success) {
    print "Content-type: application/x-x509-ca-cert\n\n";
    print $response->content;

} else {
   print "Content-type: text/html\n\n";
   print "<html>";
   print "<link rel=stylesheet href='/pki/esc/home/style.css' type='text/css'>";
   print "<center><h2>Error Importing CA Chain Information!</h2></center>";
   print "<center><h2>Please try again later.</h2></center>";
   print "</html>"
}
