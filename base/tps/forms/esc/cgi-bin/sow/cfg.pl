#! /usr/bin/perl
#
# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation.
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

use Mozilla::LDAP::Conn;
use PKI::TPS::Common;

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

sub get_ldap_secure()
{
  my $ldapsecure = `grep auth.instance.0.ssl $cfg | cut -c21-`;
  chomp($ldapsecure);
  return $ldapsecure;
}

sub get_ldap_certdir()
{
  my $ldapcertdir = `grep service.instanceDir $cfg | cut -c21-`;
  chomp($ldapcertdir);
  return $ldapcertdir . "/alias";
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

  my $x_secureconn = `grep -e "^tokendb.ssl" $cfg | cut -c13-`;
  chomp($x_secureconn);
  my $x_basedn = `grep -e "^tokendb.userBaseDN" $cfg | cut -c20-`;
  chomp($x_basedn);
  my $x_binddn = `grep -e "^tokendb.bindDN" $cfg | cut -c16-`;
  chomp($x_binddn);
  my $x_bindpwdpath = `grep -e "^tokendb.bindPassPath" $cfg | cut -c22-`;
  chomp($x_bindpwdpath);
  my $x_bindpwd = `grep -e "^tokendbBindPass" $x_bindpwdpath | cut -c17-`;
  chomp($x_bindpwd);

  my $ldap =  PKI::TPS::Common::make_connection(
                  {host => $x_host, port => $x_port, pswd => $x_bindpwd, bind => $x_binddn, cert => $x_certdir},
                  $x_secureconn);

  return 0 if (! $ldap);

  my $entry = $ldap->search ( "cn=TUS Officers,ou=Groups,$x_basedn",
                              "sub",
                              "uid=$uid",
                              0
                            );

  $ldap->close();

  if ($entry) {
     return 1;
  }
  return 0;
}

sub is_user()
{
  my ($dn) = @_;

  my $uid = $dn;
  # need to map a subject dn into user DN
  $uid =~ /uid=([^,]*)/; # retrieve the uid
  $uid = $1;

  my $x_host = get_ldap_host();
  my $x_port = get_ldap_port();
  my $x_secureconn = get_ldap_secure();
  my $x_basedn = get_base_dn();
  my $x_certdir = get_ldap_certdir();

  my $ldap = PKI::TPS::Common::make_connection(
                  {host => $x_host, port => $x_port, cert => $x_certdir},
                  $x_secureconn);

  return 0 if (! $ldap);

  my $entry = $ldap->search ( "ou=people,$x_basedn",
                              "sub",
                              "uid=$uid",
                               0
                            );

  $ldap->close();

  if ($entry) {
     return 1;
  }
  return 0;
}

