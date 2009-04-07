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

package op;

use lib $ENV{DOCUMENT_ROOT} . "/../lib/perl";

use Benchmark;
use CGI;
use Template::Velocity;
use PKI::Base::Conf;
use PKI::Base::Registry;
use PKI::Request::Queue;
use PKI::Base::Util;

use vars qw (@ISA);
use PKI::Service::Op;
@ISA = qw(PKI::Service::Op);

sub new {
  my $self = {};
  bless ($self);
  return $self;
}

sub process()
{
  my $self = shift;

  my $q = CGI->new();

  my $st = new Benchmark;

  my $util = PKI::Base::Util->new();
  my $docroot = PKI::Base::Registry->get_docroot();
  my $parser = PKI::Base::Registry->get_parser();
  my $cfg = PKI::Base::Registry->get_config();

  $self->debug_params($cfg, $q);

  if (!$self->agent_auth($cfg)) {
    print $q->redirect("/agent/error.cgi");
    return;
  }
  my $uid = $self->get_current_uid($cfg);

  my %context;
  $context{uid} = $uid;

  my $type = $util->get_val($q->param('type'));
  my $id = $util->get_val($q->param('id'));

  my $db_st = new Benchmark;
  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);

  my $ref;

  my @roles = $self->get_current_roles($cfg);
  my $pref = $queue->read_request_by_roles(\@roles, $id);

  if (! defined $pref) {
    $queue->close();
    $self->debug_log($cfg, "Invalid attempt to process request id= " . $id .
        " by userid= " . $uid);
    print $q->redirect("/agent/error.cgi");
    return;
  }

  my $curr_status = $pref->{'status'};
  if ($type eq "approve") {
    if (($curr_status ne "OPEN") && ($curr_status ne "ERROR")) {
      $queue->close();
      print $q->redirect("/agent/request/read.cgi?id=$id");
      return;
    }
 
    $ref = $queue->approve_request($id, $uid);
  } elsif ($type eq "reject") {
    if (($curr_status ne "OPEN") && ($curr_status ne "ERROR")) {
      $queue->close();
      print $q->redirect("/agent/request/read.cgi?id=$id");
      return;
    }

    $ref = $queue->reject_request($id, $uid);
  }
  $queue->close();
  my $db_et = new Benchmark;
 
  $context{data} = $util->breakline($ref->{'data'}, 40);
  $context{output} = $util->breakline($ref->{'output'}, 40);
  $context{serialno} = $ref->{'serialno'};
  $context{type} = $ref->{'type'};
  $context{ip} = $ref->{'ip'};
  $context{note} = $ref->{'note'};
  $context{note} =~ s/\n/<br\/>/g;
  $context{created_at} = $ref->{'created_at'};
  $context{updated_at} = $ref->{'updated_at'};
  $context{assigned_to} = $ref->{'assigned_to'};
  $context{processed_by} = $ref->{'processed_by'};
  $context{created_by} = $ref->{'created_by'};
  $context{status} = $ref->{'status'};
  $context{errorString} = $ref->{'errorString'};
  $context{id} = $ref->{'rowid'};

  my $t_st = new Benchmark;
  my $result = $parser->execute_file_with_context("agent/request/op.vm",
                  \%context);
  my $t_et = new Benchmark;

  my $xml = $q->param('xml');
  if ($xml eq "true") {
    print "Content-Type: text/xml\n\n";
    print $self->xml_output(\%context);
  } else {
    print "Content-Type: text/html\n\n";
    print "$result";
  }

  my $et = new Benchmark;

  $self->debug_log($cfg, "benchmark " .
                  "total=" . timestr(timediff($et, $st)) . " " .
                  "db total=" . timestr(timediff($db_et, $db_st)) . " " .
                  "template total=" . timestr(timediff($t_et, $t_st)) . " "
               );
}

my $op = op->new();
$op->execute();
