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
use PKI::Base::Conf;
use PKI::Base::Util;
use PKI::Base::Registry;
use PKI::Conn::CA;
use Encode;

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

  my $serialno = $util->get_alphanum_val($q->param('serialno'));
  my $subject_dn = $util->get_val($q->param('subject_dn'));
  my $reason = $util->get_alphanum_val($q->param('reason'));
  my $rid = $util->get_alphanum_val($q->param('rid'));

  my $ca = PKI::Conn::CA->new();
  $ca->open($cfg);
  $ca->revoke($rid, "ca1", $serialno, $reason);
  $ca->close();

  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);

  my $ref = $queue->read_request($rid);
  $context{errorString} = $util->html_encode($ref->{'errorString'});
  $queue->close();

  $context{rid} = $util->html_encode($rid);
  $context{serialno} = $util->html_encode($serialno);
  $context{subject_dn} = $util->html_encode(Encode::decode('UTF-8', $subject_dn));

  my $result = $parser->execute_file_with_context("agent/cert/submit.vm",
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
