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
  my $host = get_ldap_host();
  my $port = get_ldap_port();
  my $secureconn = get_ldap_secure();
  my $basedn = get_base_dn();
  my $certdir = get_ldap_certdir();

  if (!&authorize()) {
    print $q->redirect("/cgi-bin/sow/noaccess.cgi");
    return;
  }

  my $name = $q->param('name');
  my $uid = $q->param('name_ID');
  $name = "" if !defined $name;

  if ($name eq "") {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=Name cannot be empty");
    return;
  }

  my $conn =  PKI::TPS::Common::make_connection(
                  {host => $host, port => $port, cert => $certdir},
                  $secureconn);

  if (!$conn) {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=Failed to connect to the database.");
    return;
  };

  my $entry = $conn->search ( $basedn,
                         "sub",
                         "cn=$name",
                         0
                       );

  if (!$entry) {
    $conn->close();
    print $q->redirect("/cgi-bin/sow/search.cgi?error=User $name not found");
    return;
  }

  my $givenName = ($entry->getValues("givenName"))[0] ||  "-";
  my $cn = ($entry->getValues("cn"))[0] || "-";
  my $sn = ($entry->getValues("sn"))[0] ||"-";
  $uid = ($entry->getValues("uid"))[0] || "-";
  my $mail = ($entry->getValues("mail"))[0] || "-";
  my $phone = ($entry->getValues("telephoneNumber"))[0] || "-";
  my $photoLarge = ($entry->getValues("photoLarge"))[0] || ""; # photo (full size)
  my $photoSmall = ($entry->getValues("photoSmall"))[0] || ""; # photo (thumb)
  my $height = ($entry->getValues("height"))[0] || "";
  my $weight = ($entry->getValues("weight"))[0] || "";
  my $eyecolor = ($entry->getValues("eyeColor"))[0] || "";

  $conn->close();

  if ($uid eq "-") {
    print $q->redirect("/cgi-bin/sow/search.cgi?error=User $name not found");
    return;
  }

  open(FILE, "< read.html");

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
