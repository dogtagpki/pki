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

#######################################
# This plugins mails a notification
# to an email specified in the request.
#######################################
package PKI::Request::Plugin::RequestToCA;

use DBI;
use PKI::Base::TimeTool;
use PKI::Conn::CA;

#######################################
# Instantiate this plugin
#######################################
sub new {
  my $self = {};
  bless ($self);
  return $self;
}

#######################################
# Processes plugin
#######################################
sub process {
  my ($self, $cfg, $queue, $prefix, $req) = @_;

  my $ca = $cfg->get($prefix . ".ca");
  my $profile_id = $cfg->get($prefix . ".profileId");
  my $req_type = $cfg->get($prefix . ".reqType");

  my $server_id = "";
  my $site_id = "";
  my $csr = "";
  my $csr_type = "";

  my $data = $req->{'data'};
  foreach $nv (split(/;/, $data)) {
    my ($n, $v) = split(/=/, $nv);
    if ($n eq "server_id") {
      $server_id = $v;
    }
    if ($n eq "site_id") {
      $site_id = $v;
    }
    if ($n eq "csr") {
      $csr = $v;
    }
    if ($n eq "csr_type") {
      $csr_type = $v;
    }
  }

  if ($csr_type ne "") {
    $req_type = $csr_type;
  }

  my $ca_conn = PKI::Conn::CA->new();
  $ca_conn->open($cfg);
  my $cert = $ca_conn->enroll($req->{'rowid'}, $ca, $profile_id, $req_type, $csr);
  $queue->set_request($req->{'rowid'}, "output", $cert);
  $req->{'output'} = $cert;
  $ca_conn->close();

}

1;
