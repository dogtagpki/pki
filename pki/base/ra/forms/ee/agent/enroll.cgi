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

use MIME::Base64;
use CGI;
use PKI::Service::Op;
use Template::Velocity;
use PKI::Base::Conf;
use PKI::Base::Registry;
use PKI::Request::Queue;
use PKI::Conn::CA;
use PKI::Base::PinStore;
use PKI::Base::Util;

use vars qw (@ISA);
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

  my $uid = $util->get_val($q->param('uid'));
  my $pin = $util->get_alphanum_val($q->param('pin'));
  my $csr = $util->get_val($q->param('csr'));
  $csr = $util->normalize_csr($csr);

  my $key = $uid;

  my $pin_store = PKI::Base::PinStore->new();
  $pin_store->open($cfg);
  my $pinref = $pin_store->read_pin($key);
  if (defined($pinref) && $pinref->{'pin'} eq $pin) {
    $pin_store->delete($key);
  } else {
    $pin_store->close();
    print $q->redirect("/ee/error.cgi?error=Invalid Pin");
    return;
  }
  my $rid = $pinref->{'rid'};
  $pin_store->close();

  my $profile_id = $cfg->get("request.agent.profileId");
  my $cert_request_type = $cfg->get("request.agent.reqType");

  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);
  my $req = $queue->read_request($rid);
  $queue->set_request($rid, "subject_dn", "uid=$uid, e=$req->{'created_by'}");

  my $ca = PKI::Conn::CA->new();
  $ca->open($cfg);
  my $cert = $ca->enroll($rid, "ca1", $profile_id, $cert_request_type, $csr);
  $ca->close();
  $queue->set_request($rid, "output", $cert);

  $req = $queue->read_request($rid);
  if ($cert eq "") {
    my $error = $req->{'errorString'};
    $queue->close();
    print $q->redirect("/ee/error.cgi?error=$error");
    return;
  }

  my $decoded = decode_base64($cert);
  my $encoded = encode_base64($decoded);

  my %context;
  $context{cert} = $encoded;
  $context{rid} = $util->html_encode($rid);
  $context{subject_dn} = $util->html_encode($req->{'subject_dn'});
  $queue->close();

  my $result = $parser->execute_file_with_context("ee/agent/enroll.vm", 
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
