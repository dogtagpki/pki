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
use URI::URL;
use URI::Escape;
use XML::Simple;
use CGI;
use PKI::Base::Conf;
use PKI::Base::Util;
use PKI::Base::Registry;
use PKI::Service::Op;
use Template::Velocity;
use PKI::Conn::CA;
use PKI::Base::PinStore;

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

  my $client_id = $util->get_val($q->param('client_id'));
  my $site_id = $util->get_val($q->param('site_id'));
  my $pin = $util->get_alphanum_val($q->param('pin'));
  my $csr = $util->get_val($q->param('csr'));

  my $key = $client_id . "/" . $site_id;

  my $pin_store = PKI::Base::PinStore->new();
  $pin_store->open($cfg);
  my $pinref = $pin_store->read_pin($key);
  if (defined($pinref) && $pinref->{'pin'} eq $pin) {
    $pin_store->delete($key);
  } else {
    $pin_store->close();
    # error, redirect user back to the original enrollment page
    print $q->redirect("/ee/scep/installer.cgi");
    return;
  }
  $pin_store->close();

  my $profile_id = $cfg->get("request.scep.profileId");
  my $cert_request_type = $cfg->get("request.scep.reqType");

  my $ca = PKI::Conn::CA->new();
  $ca->open($cfg);
  my $cert = $ca->enroll($pinref->{'rid'}, "ca1", $profile_id, $cert_request_type, $csr);
  $ca->close();
  my $decoded = decode_base64($cert);
  my $encoded = encode_base64($decoded);

  my %context;
  $context{cert} = $encoded;

  my $result = $parser->execute_file_with_context("ee/scep/enroll.vm",
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
