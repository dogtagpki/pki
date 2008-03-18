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
package PKI::Request::Queue;

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
  my $timeout = $self->{dbh}->func("busy_timeout");
  $self->{dbh}->func($timeout * 10, "busy_timeout");
}

#######################################
# Creates a new request
#######################################
sub invoke_plugins {
  my ($self, $prefix, $type, $ref) = @_;

  my $num_plugins = $self->{cfg}->get($prefix . ".num_plugins");
  for (my $i = 0; $i < $num_plugins; $i++) {
    my $plugin = $self->{cfg}->get($prefix . "."  . $i . ".plugin");
    eval("require $plugin");
    my $p = $plugin->new();
    $p->process($self->{cfg}, $self, $prefix . "." . $i, $ref);
  }
}

#######################################
# Creates a new request
#######################################
sub create_request {
  my ($self, $type, $data, $meta_info, $created_by) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();

  my $insert = "insert into requests (" .
                   "type" . "," .
                   "status" . "," .
                   "errorString" . "," .
                   "ip" . "," .
                   "data" . "," .
                   "serialno" . "," .
                   "subject_dn" . "," .
                   "meta_info" . "," .
                   "created_by" . "," .
                   "updated_at" . "," .
                   "created_at" .
                 ") values (" .
                   $dbh->quote($type) . "," .
                   $dbh->quote("OPEN") . "," .
                   $dbh->quote("0") . "," .
                   $dbh->quote($ENV{REMOTE_ADDR}) . "," .
                   $dbh->quote($data) . "," .
                   $dbh->quote("unavailable") . "," .
                   $dbh->quote("unavailable") . "," .
                   $dbh->quote($meta_info) . "," .
                   $dbh->quote($created_by) . "," .
                   $dbh->quote($now) . "," .
                   $dbh->quote($now) .
                 ")";
REDO_CREATE_REQUEST:
  eval {
    $dbh->do($insert);
  };
  if ($dbh->err == 5) {
    sleep(1);
    goto REDO_CREATE_REQUEST;
  }
  my $rid = $dbh->func('last_insert_rowid');

  my $ref = $self->read_request($rid);

  # call plugins
  my $prefix = "request." . $type .  ".create_request";
  $self->invoke_plugins($prefix, $type, $ref);

  return $rid;
}

#######################################
# Reads a request
#######################################
sub read_request {
  my ($self, $reqid) = @_;
  my $dbh = $self->{dbh};
  my $select = "select *,rowid from requests " .
                    "where rowid=" . $dbh->quote($reqid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

sub read_request_by_roles {
  my ($self, $roles, $reqid) = @_;
  my $dbh = $self->{dbh};

  my $select;
  if (grep /^administrators/, @$roles) {
    # administrator see all requests
    $select = "select *,rowid from requests " .
                    "where rowid=" . $dbh->quote($reqid);
  } else {
    my $filter = $self->get_role_filter($roles);
    $select = "select *,rowid from requests where " .
                 "(" . $filter . ")" . " AND " .
                 "rowid=" . $dbh->quote($reqid);
  }
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

#######################################
# Sets request attributes
#######################################
sub set_request {
  my ($self, $reqid, $name, $value) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();
  my $update = "update requests set " . 
                    $name . "=" .  $dbh->quote($value) . "," .
                    "updated_at=" .  $dbh->quote($now) . " " .
                    "where rowid=" . $dbh->quote($reqid);
REDO_SET_REQUEST:
  eval {
    $dbh->do($update);
  };
  if ($dbh->err == 5) {
    sleep(1);
    goto REDO_SET_REQUEST;
  }

  my $select = "select *,rowid from requests " .
                    "where rowid=" . $dbh->quote($reqid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();

  return $ref;
}

#######################################
# Sets output
#######################################
sub set_request_output {
  my ($self, $reqid, $output) = @_;

  return $self->set_request($reqid, "output", $output);
}

#######################################
# Approves a request
#######################################
sub approve_request {
  my ($self, $reqid, $processed_by) = @_;
  my $dbh = $self->{dbh};

  # XXX - check assigned_to

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();
  my $update = "update requests set " .
                    "processed_by=" . $dbh->quote($processed_by) . "," .
                    "status='APPROVED' " . "," .
                    "errorString='0' " . "," .
                    "updated_at=" .  $dbh->quote($now) . " " .
                    "where rowid=" . $dbh->quote($reqid);
REDO_APPROVE_REQUEST:
  eval {
    $dbh->do($update);
  };
  if ($dbh->err == 5) {
    sleep(1);
    goto REDO_APPROVE_REQUEST;
  }

  my $select = "select *,rowid from requests " .
                    "where rowid=" . $dbh->quote($reqid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();

  # call plugins
  my $prefix = "request." . $ref->{'type'} .  ".approve_request";
  $self->invoke_plugins($prefix, $ref->{'type'}, $ref);

  my $select = "select *,rowid from requests " .
                    "where rowid=" . $dbh->quote($reqid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();

  return $ref;
}

#######################################
# Rejects a request
#######################################
sub reject_request {
  my ($self, $reqid, $processed_by) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();
  my $update = "update requests set " .
                    "processed_by=" . $dbh->quote($processed_by) . "," .
                    "status='REJECTED' " . "," .
                    "updated_at=" .  $dbh->quote($now) . " " .
                    "where rowid=" . $dbh->quote($reqid);
REDO_REJECT_REQUEST:
  eval {
    $dbh->do($update);
  };
  if ($dbh->err == 5) {
    sleep(1);
    goto REDO_REJECT_REQUEST;
  }

  my $select = "select *,rowid from requests " .
                    "where rowid=" . $dbh->quote($reqid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();

  # call plugins
  my $prefix = "request." . $ref->{'type'} .  ".reject_request";
  $self->invoke_plugins($prefix, $ref->{'type'}, $ref);

  my $select = "select *,rowid from requests " .
                    "where rowid=" . $dbh->quote($reqid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();

  return $ref;
}

sub get_role_filter {
  my ($self, $roles) = @_;
  my $dbh = $self->{dbh};

  my $filter = "";
  foreach $rr (@$roles) {
    if ($filter eq "") {
      $filter = "assigned_to=" . $dbh->quote($rr);
    } else {
      $filter = $filter . " OR " . "assigned_to=" . $dbh->quote($rr);
    }
  }
  return $filter;
}

#######################################
# Lists requests
#######################################
sub list_requests {
  my ($self, $startpos, $maxcount) = @_;
  my $dbh = $self->{dbh};
  my $select = "select *,rowid from requests " .
                    "order by rowid desc " .
                    "limit $startpos, $maxcount";
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my @reqs;
  while (my $ref = $sth->fetchrow_hashref()) {
    push(@reqs, $ref);
  }
  $sth->finish();
  return @reqs;
}

sub count_requests_by_roles {
  my ($self, $roles, $status) = @_;
  my $dbh = $self->{dbh};

  my $select;

  if (grep /^administrators$/, @$roles) {
    # administrator sees everything
    $select = "select count(*) from requests where " .
                    "status like '$status%' ";
  } else {
    # shows requests that are owned by the groups
    my $filter = $self->get_role_filter($roles);
    $select = "select count(*) from requests where " .
                    "status like '$status%' AND " .
                    "(" . $filter . ") ";
  }
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref->{'count(*)'};
}

sub list_requests_by_roles {
  my ($self, $roles, $status, $startpos, $maxcount) = @_;
  my $dbh = $self->{dbh};

  my $select;

#  if ($roles =~ /administrators/) {
  if (grep /^administrators$/, @$roles) {
    # administrator sees everything
    $select = "select *,rowid from requests where " .
                    "status like '$status%' " .
                    "order by rowid desc " .
                    "limit $startpos, $maxcount";
  } else {
    # shows requests that are owned by the groups
    my $filter = $self->get_role_filter($roles);
    $select = "select *,rowid from requests where " .
                    "status like '$status%' AND " .
                    "(" . $filter . ") " .
                    "order by rowid desc " .
                    "limit $startpos, $maxcount";
  }
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my @reqs;
  while (my $ref = $sth->fetchrow_hashref()) {
    push(@reqs, $ref);
  }
  $sth->finish();
  return @reqs;
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
