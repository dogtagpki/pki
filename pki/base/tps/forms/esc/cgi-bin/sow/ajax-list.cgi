#! /usr/bin/perl -w
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

use CGI;
use Mozilla::LDAP::Conn;
use PKI::TPS::Common;

[REQUIRE_CFG_PL]

sub main()
{

  my $q = new CGI;

  my $host = get_ldap_host();
  my $port = get_ldap_port();
  my $secureconn = get_ldap_secure();
  my $basedn = get_base_dn();
  my $certdir = get_ldap_certdir();

  my $letters = $q->param('letters');
  if ($letters eq "") {
    # HACK: ajax.js posts parameters into POST URL
    $letters = $ENV{'QUERY_STRING'};
    $letters =~ s/.*letters=//g;
    $letters =~ s/\+/ /g;
  }

  my $result = "";

  print "Content-Type: text/html\n\n";

  my $conn =  PKI::TPS::Common::make_connection(
                  {host => $host, port => $port, cert => $certdir},
                  $secureconn);

  return if (!$conn);

  my $entry = $conn->search ( { base =>$basedn,
                                scope => "sub",
                                filter => "cn=$letters*",
                                attrsonly => 0,
                                attrs => qw(cn uid),
                                sortattrs => qw(cn)}
                            );

  while ($entry) {
    my $cn =  ($entry->getValues("cn"))[0]  || "";
    my $uid = ($entry->getValues("uid"))[0] || "";
    $result .= $uid . "###" . $cn . "|";
    $entry  $conn->nextEntry();
  }

  $conn->close();

  print $result;
}

&main();
