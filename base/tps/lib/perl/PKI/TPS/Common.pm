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

package PKI::TPS::Common;

use strict;
use warnings;
use Exporter;
use Mozilla::LDAP::Conn;
use Mozilla::LDAP::LDIF;

use vars qw(@ISA @EXPORT @EXPORT_OK);
@ISA = qw(Exporter Autoloader);
@EXPORT = qw(r yes no import_ldif test_and_make_connection make_connection);

$PKI::TPS::Common::VERSION = '1.00';

sub yes { 
  return sub {1}; 
}

sub no { 
  return sub {0}; 
}

sub r { 
  my $a = shift; 
  return sub { $a; } 
}

# special function to add schema elements.  This assumes the entry
# is ldif update format with changetype "modify" and operation "add"
#
sub add_schema_update
{
    my ($conn, $aentry, $err_ref) = @_;

    my $sentry = $conn->search($aentry->{dn}, "base", "(objectclass=*)", 0, ("*", "aci"));
    if (!$sentry) {
        $$err_ref .= "Error: trying to update entry that does not exist: " . $aentry->{dn} . "\n"; 
        return 0;
    }

    my @addtypes = ("attributeTypes", "objectClasses");

    foreach my $attr (@addtypes) {
        my @vals = $aentry->getValues($attr);
        my @values = ("dummyAttr: dummy value", @vals); # this dummy entry consumes the error 53
        foreach my $val (@values) {
            $sentry->addValue( $attr, $val );
            $conn->update($sentry);
            my $rc = $conn->getErrorCode();
            if ( $rc != 0 ) {
                my $string = $conn->getErrorString();
                $$err_ref .= "Error: updating entry " . $sentry->{dn} . " with value $val : $string\n";
            } else {
               $$err_ref .= "Updated entry ". $sentry->{dn} . " with value $val : rc = $rc\n";
            }
        }
    }
    return 1;
}

sub import_ldif
{
  my ($conn, $ldif_file, $msg_ref, $schema) = @_;

  if (!open( MYLDIF, "$ldif_file" )) {
    $$msg_ref = "Could not open $ldif_file: $!\n";
    return 0;
  }

  my $in = new Mozilla::LDAP::LDIF(*MYLDIF);
  while (my $entry = readOneEntry $in) {
    if (defined($schema) && ($schema == 1)) {
        add_schema_update($conn, $entry, $msg_ref);
    } else {
        if (!$conn->add($entry)) {
            $$msg_ref .= "Error: could not add entry " . $entry->getDN() . ":" . $conn->getErrorString() . "\n";
        }
    }
  }
  close( MYLDIF );
  return 1;
}

# this subroutine checks if an ldaps connection is successful first
# and then if an ldap connection is successful.
# This prevents a hanging condition when someone tries to connect to a ldaps
# port using LDAP
#
# The arg hash is assumed to have the certdir (key == cert) defined.

sub test_and_make_connection
{
  my  ($arg_ref, $secureconn, $msg_ref) = @_;
  my $conn = new Mozilla::LDAP::Conn($arg_ref);
  if ($conn) { #ldaps succeeds
    if ($secureconn eq "false") {
      $$msg_ref = "SSL not selected, but this looks like an SSL port.";
      return undef;
    }
  } else { #ldaps failed
    if ($secureconn eq "true") {
      $$msg_ref = "Failed to connect to LDAPS port";
      return undef;
    }
    delete $arg_ref->{cert};
    $conn = new Mozilla::LDAP::Conn($arg_ref);
    if (!$conn) { # ldap failed
      $$msg_ref = "Failed to connect to LDAP port:";
      return undef;
    }
  }
  return $conn;
}

sub make_connection
{
  my ($arg_ref, $secureconn) = @_;
  if ($secureconn eq "false") {
    delete $arg_ref->{cert};
  }
  return new Mozilla::LDAP::Conn($arg_ref);
}

1;
