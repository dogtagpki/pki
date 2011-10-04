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
package PKI::Base::UserStore;

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
# Opens this store
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
# Maps user
#######################################
sub map_user {
  my ($self, $certificate) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from users " .
                    "where " .
                    "certificate=" . $dbh->quote($certificate);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

#######################################
# Gets roles of the given user
#######################################
sub get_roles {
  my ($self, $uid) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from roles " .
                    "where " .
                    "uid=" . $dbh->quote($uid);
  my @roles;
  my $sth = $dbh->prepare($select);
  $sth->execute();
  while (my $ref = $sth->fetchrow_hashref()) {
    push(@roles, $ref->{'gid'});
  }
  $sth->finish();
  return @roles;
}


#######################################
# Reads a user
#######################################
sub read_group {
  my ($self, $gid) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from groups " .
                    "where gid=" . $dbh->quote($gid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

sub read_user {
  my ($self, $uid) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from users " .
                    "where uid=" . $dbh->quote($uid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();
  return $ref;
}

sub set_user {
  my ($self, $uid, $name, $value) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();
  my $update = "update users set " . 
                    $name . "=" .  $dbh->quote($value) . "," .
                    "updated_at=" .  $dbh->quote($now) . " " .
                    "where uid=" . $dbh->quote($uid);
  $dbh->do($update);

  my $select = "select * from users " .
                    "where uid=" . $dbh->quote($uid);
  my $sth = $dbh->prepare($select);
  $sth->execute();
  my $ref = $sth->fetchrow_hashref();
  $sth->finish();

  return $ref;
}

#######################################
# Lists all members in the given group
#######################################
sub list_all_members {
  my ($self, $gid) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from roles where " .
                    "gid=" . $dbh->quote($gid) . " " .
                    "order by uid desc ";
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
# Lists
#######################################
sub list_all_non_members {
  my ($self, $gid) = @_;
  my $dbh = $self->{dbh};
  # find members of the given group
  my $select1 = "select * from roles where " .
                    "gid=" . $dbh->quote($gid);
  my $sth1 = $dbh->prepare($select1);
  $sth1->execute();
  my $filter = "";
  while (my $ref1 = $sth1->fetchrow_hashref()) {
    if ($filter eq "") {
      $filter = "uid<>" . $dbh->quote($ref1->{'uid'});
    } else {
      $filter = $filter . " AND " . "uid<>" . $dbh->quote($ref1->{'uid'});
    }
  }
  $sth1->finish();

  my $select;
  if ($filter eq "") {
    $select = "select * from users " .
                    "order by uid desc ";
  } else {
    $select = "select * from users where (" .
                    $filter . ") " .
                    "order by uid desc ";
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

sub delete_user {
  my ($self, $userid) = @_;
  my $dbh = $self->{dbh};

  my $cmd = "delete from roles where uid=" . $dbh->quote($userid);
  $dbh->do($cmd);
  $cmd = "delete from users where uid=" . $dbh->quote($userid);
  $dbh->do($cmd);
}

sub add_user_to_group {
  my ($self, $gid, $userid) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();

  my $cmd = "insert into roles (" . 
                   "gid" . "," .
                   "uid" .
               ") values (" .
                   $dbh->quote($gid) . "," .
                   $dbh->quote($userid) .
               ")";
  $dbh->do($cmd);
}

sub delete_user_from_group {
  my ($self, $gid, $userid) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();

  my $cmd = "delete from roles where " .
                   "gid=" . $dbh->quote($gid) . " AND " .
                   "uid=" . $dbh->quote($userid);
  $dbh->do($cmd);
}

sub add_user {
  my ($self, $userid, $name, $email, $certificate) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();

  my $cmd = "insert into users (" . 
                   "uid" . "," .
                   "name" . "," .
                   "email" . "," .
                   "certificate" . "," .
                   "created_at" .
               ") values (" .
                   $dbh->quote($userid) . "," .
                   $dbh->quote($name) . "," .
                   $dbh->quote($email) . "," .
                   $dbh->quote($certificate) . "," .
                   $dbh->quote($now) .
               ")";
REDO_ADD_USER:
  eval {
    $dbh->do($cmd);
  };
  if ($dbh->err == 5) {
    sleep(1);
    goto REDO_ADD_USER;
  }
}

sub add_group {
  my ($self, $gid, $name) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();

  my $cmd = "insert into groups (" . 
                   "gid" . "," .
                   "name" . "," .
                   "created_at" .
               ") values (" .
                   $dbh->quote($gid) . "," .
                   $dbh->quote($name) . "," .
                   $dbh->quote($now) .
               ")";
REDO_ADD_GROUP:
  eval {
    $dbh->do($cmd);
  };
  if ($dbh->err == 5) {
    sleep(1);
    goto REDO_ADD_GROUP;
  }
}

sub delete_group {
  my ($self, $gid) = @_;
  my $dbh = $self->{dbh};

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();

  my $cmd = "delete from roles where gid=" . $dbh->quote($gid);
  $dbh->do($cmd);
  $cmd = "delete from groups where gid=" . $dbh->quote($gid);
  $dbh->do($cmd);
}

sub list_users {
  my ($self, $startpos, $maxcount) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from users " .
                    "order by uid desc " .
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

sub list_groups {
  my ($self, $startpos, $maxcount) = @_;
  my $dbh = $self->{dbh};
  my $select = "select * from groups " .
                    "order by gid desc " .
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
#######################################
# Closes this store
#######################################
sub close {
  my ($self) = @_;
  my $dbh = $self->{dbh};
  $dbh->disconnect();
}

1;
