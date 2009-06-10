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

use DBI;
use CGI;
use Template::Velocity;
use PKI::RA::GlobalVar;
use PKI::Base::Conf;
use PKI::Base::Util;
use PKI::Base::Registry;
use PKI::Request::Queue;
use PKI::Service::Op;

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
  $self->debug_log( $cfg, "in request/index.cgi, uid == $uid");

  my %context;
  $context{uid} = $util->html_encode($uid);

  my @roles = $self->get_current_roles($cfg);
#  my $r = join(",",@roles);

  my $status = $util->get_alphanum_val($q->param('status'));
  if ($status eq "") {
    $context{status} = "";
  } else {
    $context{status} = $util->html_encode($status);
  }

  my $sp = $util->get_alphanum_val($q->param('sp'));
  if ($sp eq "") {
    $sp = "0";
  }
  $context{sp} = $sp;
  my $mc = $util->get_alphanum_val($q->param('mc'));
  if ($mc eq "") {
    $mc = "20";
  }
  $context{mc} = $mc;
  $context{pp} = $sp - $mc; # previous pos (for paging)
  $context{np} = $sp + $mc; # next pos (for paging)

  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);
  my $total = $queue->count_requests_by_roles(\@roles, $status);
  $context{total} = $util->html_encode($total);

  my @reqs = $queue->list_requests_by_roles(\@roles, $status, $sp, $mc);
#  my @reqs = $queue->list_requests_by_roles($r, $status, $sp, $mc);
  $queue->close();

  my @r;
  my $i = 0;
  foreach my $req (@reqs) {
    $r[$i] = new PKI::RA::GlobalVar(
                    getId => sub { return $util->html_encode($req->{'rowid'}) },
                    getType => sub { return $util->html_encode($req->{'type'}) },
                    getStatus => sub { return $util->html_encode($req->{'status'}) },
                    getError => sub { return $util->html_encode($req->{'errorString'}) },
                    getAssignedTo => sub { return $util->html_encode($req->{'assigned_to'}) },
                    getData => sub { return $util->html_encode($req->{'data'}); },
                    getCreatedBy => sub { return $util->html_encode($req->{'created_by'}); },
                    getCreatedAt => sub { return $util->html_encode($req->{'created_at'}); },
                   );
    $i++;
  }
  $context{rows} = \@r;

  if ($sp - $mc < 0) {
    $context{show_previous} = "no";
  } else {
    $context{show_previous} = "yes";
  }

  if ($i < 20) {
    $context{show_next} = "no";
  } else {
    $context{show_next} = "yes";
  }

  my $result = $parser->execute_file_with_context("agent/request/index.vm",
                  \%context);

  my $xml = $q->param('xml');
  if ($xml eq "true") {
    print "Content-Type: text/xml\n\n";
    print $self->xml_output(\%context);
  } else {
    print "Content-Type: text/html\n\n";
    print "$result";
  }
}

my $op = op->new();
$op->execute();
