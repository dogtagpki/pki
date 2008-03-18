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

require "./cfg.pl";

my $ldapHost = get_ldap_host();
my $ldapPort = get_ldap_port();
my $basedn = get_base_dn();
my $ldapsearch = get_ldapsearch();

sub main()
{

  my $q = new CGI;

  my $letters = $q->param('letters');
  if ($letters eq "") {
    # HACK: ajax.js posts parameters into POST URL
    $letters = $ENV{'QUERY_STRING'};
    $letters =~ s/.*letters=//g;
    $letters =~ s/\+/ /g;
  }

  my $tmpfile = "/tmp/ajax-list-$$.txt";
  my $cmd = $ldapsearch . " " .
            "-b \"" .  $basedn . "\" " .
            "-h \"" . $ldapHost . "\" " .
            "-p \"" . $ldapPort ."\" " .
            "-S \"cn\" " .
            "-1 -s sub \"(cn=" . $letters . "*)\" cn uid > " . $tmpfile;
  system($cmd);

  my $result = "";
  open(F, "<$tmpfile");
  my $cn;
  my $uid;
  while (<F>) {
    if (/cn/) {
      $cn = $_;
      chomp($cn);
      $cn =~ s/cn: //g;
      $uid = <F>;
      chomp($uid);
      $uid =~ s/uid: //g;
      $result .= $uid . "###" . $cn . "|";
    }
  }
  close(F);
  system("rm $tmpfile");

  print "Content-Type: text/html\n\n";
  print $result;
}

&main();
