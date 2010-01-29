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

[REQUIRE_CFG_PL]


my $ldapHost = get_ldap_host();
my $ldapPort = get_ldap_port();
my $basedn = get_base_dn();
my $ldapsearch = get_ldapsearch();

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

sub DoPage
{
  my $q = new CGI;

  if (!&authorize()) {
    print $q->redirect("/cgi-bin/sow/noaccess.cgi");
    return;
  }

  my $name = $q->param('name');
  my $uid = $q->param('name_ID');

  if ($name eq "") {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=Name cannot be empty");
    return;
  }

  my $tmpfile = "/tmp/read-$$.txt";
  my $cmd = $ldapsearch . " " .
            "-b \"" . $basedn . "\" " .
            "-h \"" . $ldapHost . "\" " .
            "-p \"" . $ldapPort ."\" " .
            "-1 \"(cn=" . $name . ")\" > " . $tmpfile;
  system($cmd);

  open(F, "<$tmpfile");

  my $givenName = "-";
  my $cn = "-";
  my $sn = "-";
  $uid = "-";
  my $mail = "-";
  my $phone = "-";
  my $photoLarge = ""; # photo (full size)
  my $photoSmall = ""; # photo (thumb)
  my $height = "";
  my $weight = "";
  my $eyecolor = "";

  # get ldap values into internal varibles
  while (<F>) {
    if (/mail: (.*)/) {
      $mail = $1;
    } 
    if (/uid: (.*)/) {
      $uid = $1;
    } 
    if (/givenName: (.*)/) {
      $givenName = $1;
    } 
    if (/sn: (.*)/) {
      $sn = $1;
    } 
    if (/cn: (.*)/) {
      $cn = $1;
    } 
    if (/telephoneNumber: (.*)/) {
      $phone = $1;
    } 
    if (/photoLarge: (.*)/) {
      $photoLarge = $1;
    } 
    if (/photoSmall: (.*)/) {
      $photoSmall = $1;
    } 
    if (/height: (.*)/) {
      $height = $1;
    } 
    if (/weight: (.*)/) {
      $weight = $1;
    } 
    if (/eyeColor: (.*)/) {
      $eyecolor = $1;
    } 
  }
  close(F);

  system("rm $tmpfile");

  if ($uid eq "-") {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=User $name not found");
    return;
  }

  open(FILE, "< read_temp.html");

  print $q->header();

  while ($l = <FILE>)
  {
      $l =~ s/\$mail/$mail/g;
      $l =~ s/\$uid/$uid/g;
      $l =~ s/\$givenName/$givenName/g;
      $l =~ s/\$sn/$sn/g;
      $l =~ s/\$cn/$cn/g;
      $l =~ s/\$phone/$phone/g;
      $l =~ s/\$photoLarge/$photoLarge/g;
      $l =~ s/\$photoSmall/$photoSmall/g;
      $l =~ s/\$height/$height/g;
      $l =~ s/\$weight/$weight/g;
      $l =~ s/\$eyecolor/$eyecolor/g;
      print $l;
  }

  close(FILE);
}

&DoPage(); 
