#! /usr/bin/perl
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
# Establish platform-dependent variables:
#
my $ldapsearch="/usr/bin/ldapsearch";

#
# Feel free to modify the following parameters:
#
my $ldapHost = "localhost";
my $ldapPort = "389";
my $basedn = "ou=People,dc=sfbay,dc=redhat,dc=com";
my $port = "7888";
my $secure_port = "7889";
my $host = "localhost";

my $cfg = "/var/lib/pki-tps/conf/CS.cfg";

sub get_ldapsearch()
{
  return $ldapsearch;
}

sub get_ldap_host()
{
  my $ldapport = `grep auth.instance.0.hostport $cfg | cut -c26-`;
  chomp($ldapport);
  my ($ldapHost, $p) = split(/:/, $ldapport);
  return $ldapHost;
}

sub get_ldap_port()
{
  my $ldapport = `grep auth.instance.0.hostport $cfg | cut -c26-`;
  chomp($ldapport);
  my ($p, $ldapPort) = split(/:/, $ldapport);
  return $ldapPort;
}

sub get_base_dn()
{
  my $basedn = `grep auth.instance.0.baseDN $cfg | cut -c24-`;
  chomp($basedn);
  return $basedn;
}

sub get_port()
{
  my $port = `grep service.unsecurePort $cfg | cut -c22-`;
  chomp($port);
  return $port;
}

sub get_secure_port()
{
  my $secure_port = `grep service.securePort $cfg | cut -c20-`;
  chomp($secure_port);
  return $secure_port;
}

sub get_host()
{
  my $host = `grep service.machineName $cfg | cut -c21-`;
  chomp($host);
  return $host;
}

sub is_agent()
{
  my ($dn) = @_;

  my $uid = $dn;
  # need to map a subject dn into user DN
  $uid =~ /uid=([^,]*)/; # retrieve the uid
  $uid = $1;

  my $x_hostport = `grep -e "^tokendb.hostport" $cfg | cut -c18-`;
  chomp($x_hostport);
  my ($x_host, $x_port) = split(/:/, $x_hostport);
  my $x_basedn = `grep -e "^tokendb.userBaseDN" $cfg | cut -c20-`;
  chomp($x_basedn);
  my $x_binddn = `grep -e "^tokendb.bindDN" $cfg | cut -c16-`;
  chomp($x_binddn);
  my $x_bindpwdpath = `grep -e "^tokendb.bindPassPath" $cfg | cut -c22-`;
  chomp($x_bindpwdpath);
  my $x_bindpwd = `grep -e "^tokendbBindPass" $x_bindpwdpath | cut -c17-`;
  chomp($x_bindpwd);

   my $cmd = $ldapsearch . " " .
            "-x" .
            "-D \"" . $x_binddn . "\" " .
            "-w \"" . $x_bindpwd . "\" " .
            "-b \"" . "cn=TUS Officers,ou=Groups,".$x_basedn . "\" " .
            "-h \"" . $x_host . "\" " .
            "-p \"" . $x_port ."\" " .
            "-LLL \"(uid=" . $uid . "*)\" | wc -l";

  my $matched = `$cmd`;

  chomp($matched);

  if ($matched eq "0" || $matched eq "") {
    return 0;
  } else {
    return 1;
  }
}

sub is_user()
{
  my ($dn) = @_;

  my $uid = $dn;
  # need to map a subject dn into user DN
  $uid =~ /uid=([^,]*)/; # retrieve the uid
  $uid = $1;

  my $x_host = get_ldap_host();
  $x_port = get_ldap_port();
  my $x_basedn = get_base_dn();
  chomp($x_basedn);
  my $x_binddn = `grep -e "^tokendb.bindDN" $cfg | cut -c16-`;
  chomp($x_binddn);
  my $x_bindpwdpath = `grep -e "^tokendb.bindPassPath" $cfg | cut -c22-`;
  chomp($x_bindpwdpath);
  my $x_bindpwd = `grep -e "^tokendbBindPass" $x_bindpwdpath | cut -c17-`;
  chomp($x_bindpwd);

   my $cmd = $ldapsearch . " " .
            "-x" .
            "-D \"" . $x_binddn . "\" " .
            "-w \"" . $x_bindpwd . "\" " .
            "-b \"" . "ou=people,".$x_basedn . "\" " .
            "-h \"" . $x_host . "\" " .
            "-p \"" . $x_port ."\" " .
            "-LLL \"(uid=" . $uid . "*)\" | wc -l";


  my $matched = `$cmd`;

  chomp($matched);

  if ($matched eq "0" || $matched eq "") {
    return 0;
  } else {
    return 1;
  }
}
