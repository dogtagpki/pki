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

use CGI;
use Template::Velocity;
use PKI::Base::Conf;
use PKI::Base::Util;
use PKI::Base::Registry;
use PKI::Request::Queue;
use PKI::Base::TimeTool;

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

  my %context;
  $context{uid} = $util->html_encode($uid);

  my $id = $util->get_alphanum_val($q->param('id'));
  my $note = $util->get_val($q->param('note'));

  if ($note eq "") {
    # dont add anything
    print $q->redirect("/agent/request/read.cgi?id=" . $id);
    return;
  }

  my $timet = PKI::Base::TimeTool->new();
  my $now = $timet->get_time();
  my $new_note = "==== Note created by $uid at $now ====\n" .
                   $note . "\n";

  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);
  my $ref = $queue->read_request($id);
  $queue->set_request($id, "note", $ref->{'note'} . $new_note);
  $queue->close();

  print $q->redirect("/agent/request/read.cgi?id=" . $id);
}

my $op = op->new();
$op->execute();
