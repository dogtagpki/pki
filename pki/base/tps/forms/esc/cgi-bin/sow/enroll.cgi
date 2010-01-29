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
########################################################################
#    
# Script: esc.cgi  
# Author: Kin Blas ()
# Date:   12/19/2003
#
# CGI.pm Docs:
#    
#    http://stein.cshl.org/WWW/software/CGI/
#    
########################################################################

[REQUIRE_CFG_PL]

use CGI;

my $ldapHost = get_ldap_host();
my $ldapPort = get_ldap_port();
my $basedn = get_base_dn();
my $port = get_port();
my $host = get_host();
my $secure_port = get_secure_port();
my $ldapsearch = get_ldapsearch();

$gQuery = new CGI;

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
  if (!&authorize()) {
    print $gQuery->redirect("/cgi-bin/sow/noaccess.cgi");
    return;
  }

  $gQueryAction = "default";
  $gQueryOverrideAction = "default";

  @gCookieNames = ("ascScreenName",
                 "ascSubscriptionType",
                 "ascBindings");

  $gQueryAction = $gQuery->param("action") if 
            (defined $gQuery->param("action"));

  $gQueryOverrideAction = $gQuery->param("override_action") 
				if (defined $gQuery->param("override_action"));

  if ($gQueryOverrideAction ne "default") 
  {
    $gQueryAction = $gQueryOverrideAction;
  }

########################################################################
#
# If no action was provided, we default to showing our
# admin page!
#
#   http://www.foo.com/esc.cgi
#
########################################################################

  if ($gQueryAction eq "default")
  {
    GenerateEnrollmentPage(); 
    exit 0;
  }
}

sub ExitError
{
  my($str) = @_;
  print $gQuery->header(), $gQuery->start_html(), $str, $gQuery->end_html();
  exit 0;
}

sub GetScreenName
{
  my $sn = "";

  if (defined $gQuery->param("screenname"))
  {
    $sn = $gQuery->param("screenname");
  } else {
    $sn = "default";
  }

  return $sn;
}

sub GetKeyType
{
  my $keyType = 0;

  if (defined $gQuery->param("keytype"))
  {
    $keyType = $gQuery->param("keytype");
  }

  return $keyType;
}

sub GetKeyID
{
  my $keyID = "";

  if (defined $gQuery->param("keyid"))
  {
    $keyID = $gQuery->param("keyid");
  }

  return $keyID;
}

sub GetKeyLabelArg
{
  my $keyLabel = "";

  if (defined $gQuery->param("keylabel"))
  {
    $keyLabel = $gQuery->param("keylabel");
  }

  return $keyLabel;
}

sub HaveScreenName
{
  return 1 if (GetScreenName() ne "");
  return 0;
}

sub IsSubscriber
{
  my $subType = $gUserObj{'SUBSCRIPTION'};
  return 1 if ($subType eq "HouseKey" || $subType eq "NetKey");

  return 0;
}

sub GetNextAction
{
  my($nextActn) = "default";

  if (defined $gQuery->param('nextaction'))
  {
    $nextActn = $gQuery->param('nextaction');
  }
  elsif (defined $gQuery->param('action'))
  {
    $nextActn = $gQuery->param('action');
  }

  return $nextActn;
}

sub GenerateEnrollmentPage
{
  my ($l);

  ExitError("Failed to load enrollment page!") if (!open(ENROLL_FILE, "< enroll.html"));

  print $gQuery->header();

  my $uid = $gQuery->param("uid");

  my $tmpfile = "/tmp/read-$$.txt";
  my $cmd = $ldapsearch . " " .
            "-b \"" . $basedn . "\" " .
            "-h \"" . $ldapHost . "\" " .
            "-p \"" . $ldapPort ."\" " .
            "-1 \"(uid=" . $uid . ")\" > " . $tmpfile;
  system($cmd);

  open(F, "<$tmpfile");

  my $givenName = "-";
  my $cn = "-";
  my $sn = "-";
  $uid = "-";
  my $mail = "-";
  my $phone = "-";
  my $departmentNumber = ""; # photo (full size)
  my $employeeNumber = ""; # photo (thumb)

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
    if (/departmentNumber: (.*)/) {
      $departmentNumber = $1;
    }
    if (/employeeNumber: (.*)/) {
      $employeeNumber = $1;
    }
  }
  close(F);

  system("rm $tmpfile");


  while ($l = <ENROLL_FILE>)
  {
    $l =~ s/\$mail/$mail/g;
    $l =~ s/\$uid/$uid/g;
    $l =~ s/\$givenName/$givenName/g;
    $l =~ s/\$sn/$sn/g;
    $l =~ s/\$cn/$cn/g;
    $l =~ s/\$phone/$phone/g;
    $l =~ s/\$departmentNumber/$departmentNumber/g;
    $l =~ s/\$employeeNumber/$employeeNumber/g;
    $l =~ s/\$host/$host/g;
    $l =~ s/\$port/$port/g;
    $l =~ s/\$secure_port/$secure_port/g;
    print $l;
  }

  close(ENROLL_FILE);
}

&DoPage();
