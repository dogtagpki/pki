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
package PKI::Base::CertStore;

use DBI;
use PKI::Base::TimeTool;

#######################################
# Constructs a cert store
#######################################
sub new {
  my $self = {};
  bless ($self);
  return $self;
}

#######################################
# Opens this store
#######################################
sub open {
  my ($self, $cfg) = @_;
  $self->{cfg} = $cfg;
  my $dbfile = $cfg->get("database.dbfile");
  $self->{dbh} = DBI->connect("dbi:SQLite:dbname=$dbfile","","");
}

sub read_certificate {
  my ($self, $serialno) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from certificates " .
                    "where serialno=" . $dbh->quote($serialno);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

sub map_certificate {
  my ($self, $certificate) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from certificates " .
               "where " .
               "certificate=" . $dbh->quote($certificate);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

sub read_certificate_by_approver {
  my ($self, $uid, $serialno) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from certificates " .
                    "where approved_by=". $dbh->quote($uid).
                    "AND serialno=" . $dbh->quote($serialno);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

sub list_certs_by_approver {
  my ($self, $uid, $startpos, $maxcount) = @_;
  my $dbh = $self->{dbh};
  my $select = "select *,approved_by from certificates " .
               "where " .
               "approved_by=". $dbh->quote($uid).
               " limit $startpos, $maxcount";

  my $sth = $dbh->prepare($select);
  $sth->execute();
  my @certs;
  while (my $ref = $sth->fetchrow_hashref()) {
    push(@certs, $ref);
  }
  $sth->finish();
  return @certs;


}

sub add_certificate {
  my ($self, $serialno, $csr, $subject_dn, $certificate, $reqid, $approved_by) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();

  # sqlite is not thread safe, do our own lock here
  my $cmd = "insert into certificates (" . 
                   "subject_dn" . "," .
                   "certificate" . "," .
                   "csr" . "," .
                   "serialno" . "," .
                   "rid" . "," .
                   "approved_by" . "," .
                   "created_at" .
               ") values (" .
                   $dbh->quote($subject_dn) . "," .
                   $dbh->quote($certificate) . "," .
                   $dbh->quote($csr) . "," .
                   $dbh->quote($serialno) . "," .
                   $dbh->quote($reqid) . "," .
                   $dbh->quote($approved_by) . "," .
                   $dbh->quote($now) .
               ")";
REDO_ADD_CERT:
  eval {
    $dbh->do($cmd);
  };
  if ($dbh->err == 5) {
    sleep(1);
    goto REDO_ADD_CERT;
  }

}

#######################################
# Closes this store
#######################################
sub close {
  my ($self) = @_;
  my $dbh = $self->{dbh};
  $dbh->disconnect();
}

1;
