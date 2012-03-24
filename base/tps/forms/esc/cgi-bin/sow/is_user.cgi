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

use CGI::Carp qw(fatalsToBrowser);

[REQUIRE_CFG_PL]


my $ldapHost = get_ldap_host();
my $ldapPort = get_ldap_port();
my $basedn = get_base_dn();

my $q = new CGI;

sub authorize
{
  my $client_dn = $ENV{'SSL_CLIENT_S_DN'};
  $client_dn =~ tr/A-Z/a-z/; # all lower cases
  $client_dn =~ s/\s+//g;    # remove all spacing

  if (&is_agent($client_dn)) {
    return 1;
  }
  return 0;
}

sub DoIsUser
{

  print "Content-type: text/xml\n\n";
  
  if (!&authorize()) {
    return;
  }

  my $uid = $q->param('uid');

  if(&is_user("uid=$uid"))
  {
      print "<response>yes</response>\n";
  }
  else
  {
      print "<response>no</response>\n";
  }

}

&DoIsUser(); 
