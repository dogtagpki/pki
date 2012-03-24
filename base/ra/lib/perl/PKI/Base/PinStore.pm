#!/usr/bin/perl
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
#
#
package PKI::Base::PinStore;

use DBI;
use PKI::Base::TimeTool;

#######################################
# Constructs a request queue
#######################################
sub new {
  my $self = {};
  bless ($self);
  return $self;
}

#######################################
# Opens request queue
#######################################
sub open {
  my ($self, $cfg) = @_;
  $self->{cfg} = $cfg;
  my $dbfile = $cfg->get("database.dbfile");
  $self->{dbh} = DBI->connect("dbi:SQLite:dbname=$dbfile","","");
}

#######################################
# Creates a new request
#######################################
sub generate_random
{
    my $low = $_[0];
    my $high = $_[1];

    my $number = 0;

    if( $low >= $high || $low < 0 || $high < 0 ) {
        return -1;
    }

    $number = int( rand( $high -$low +1 ) ) + $low;

    return $number;
}


# arg0 length of string
# return random string
sub generate_random_string()
{
    my $length_of_randomstring=shift;  # the length of the string

    my @chars=( 'a'..'z','A'..'Z','0'..'9' );
    my $random_string;

    foreach( 1..$length_of_randomstring ) {
        $random_string .= $chars[rand @chars];
    }

    return $random_string;
}

sub create_pin {
  my ($self, $key, $rid, $created_by) = @_;
  my $dbh = $self->{dbh};

  my $pin = &generate_random_string(10);
  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();

  # delete previous pin
  my $delete = "delete from pins where key=" . $dbh->quote($key);
  $dbh->do($delete);

  my $insert = "insert into pins (" .
                   "key" . "," .
                   "pin" . "," .
                   "rid" . "," .
                   "created_by" . "," .
                   "created_at" .
                 ") values (" .
                   $dbh->quote($key) . "," .
                   $dbh->quote($pin) . "," .
                   $dbh->quote($rid) . "," .
                   $dbh->quote($created_by) . "," .
                   $dbh->quote($now) .
                 ")";
REDO_CREATE_PIN:
  eval {
    $dbh->do($insert);
  };
  if ($dbh->err == 5) {
    sleep(1);
    goto REDO_CREATE_PIN;
  }

  my $rid = $dbh->func('last_insert_rowid');

#  my $ref = $self->read_pin($rid);

  return $pin;
}

#######################################
# Matches pin
#######################################
sub match {
  my ($self, $key, $pin) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from pins " .
                    "where " .
                    "key=" . $dbh->quote($key) . " AND " .
                    "pin=" . $dbh->quote($pin);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  if (defined($ref)) {
    return 1;
  } else {
    return 0;
  }
}

sub read_pin {
  my ($self, $key) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from pins " .
                    "where " .
                    "key=" . $dbh->quote($key);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

#######################################
# Deletes pin
#######################################
sub delete {
  my ($self, $key) = @_;
  my $dbh = $self->{dbh};
  my $cmd = "delete from pins " .
                    "where " .
                    "key=" . $dbh->quote($key);
  $dbh->do($cmd);
}

#######################################
# Closes request queue
#######################################
sub close {
  my ($self) = @_;
  my $dbh = $self->{dbh};
  $dbh->disconnect();
}

1;
