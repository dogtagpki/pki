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
# This plugins creates a one time pin.
#######################################
package PKI::Request::Plugin::CreatePin;

use DBI;
use PKI::Base::TimeTool;
use PKI::Base::PinStore;

#######################################
# Instantiates this plugin
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

  my $pin_store = PKI::Base::PinStore->new();
  $pin_store->open($cfg);


  my $pin_format = $cfg->get($prefix . ".pinFormat");

  my $client_id = "";
  my $site_id = "";

  my $data = $req->{'data'};
  foreach $nv (split(/;/, $data)) {
    my ($n, $v) = split(/=/, $nv);
    $pin_format =~ s/\$$n/$v/g;
  }
  my $created_by = "admin";
  my $pin = $pin_store->create_pin($pin_format, $req->{'rowid'}, $created_by);

  # save pin to output
  $output = "pin=" . $pin;
  $queue->set_request_output($req->{'rowid'}, $output);

  $req->{'output'} = $output;

  $pin_store->close();
}

1;
