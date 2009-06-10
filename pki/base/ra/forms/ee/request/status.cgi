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
use PKI::Service::Op;
use PKI::Base::Conf;
use PKI::Base::Util;
use PKI::Base::Registry;
use PKI::Request::Queue;
use Template::Velocity;

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

  my $id = $util->get_alphanum_val($q->param('id'));

  my $docroot = PKI::Base::Registry->get_docroot();
  my $parser = PKI::Base::Registry->get_parser();
  my $cfg = PKI::Base::Registry->get_config();

  $self->debug_params($cfg, $q);

  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);
  my $req = $queue->read_request($id);
  $queue->close();
  if ($req == "") {
    print $q->redirect("/ee/error.cgi?error=request%20not%20found");
    return;
  }

  my %context;
  $context{id} = $util->html_encode($req->{'rowid'});
  $context{type} =$util->html_encode($req->{'type'});
  $context{status} = $util->html_encode($req->{'status'});
  $context{serialno} = $util->html_encode($req->{'serialno'});
  $context{errorString} = $util->html_encode($req->{'errorString'});

  my $result = $parser->execute_file_with_context("ee/request/status.vm",
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
