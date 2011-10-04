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
use PKI::Service::Op;
use Template::Velocity;
use PKI::Conn::CA;
use PKI::Base::PinStore;
use PKI::Base::Registry;

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

  my $operation = $util->get_alphanum_val($q->param('operation'));
  my $message = $util->get_val($q->param('message'));
  $message = uri_escape($message);

  my $ca = PKI::Conn::CA->new();
  $ca->open($cfg);
  if ($operation eq "GetCACert") {
    my $content = $ca->scep_get_ca_cert("ca1", $operation, $message);

    print "Content-Type: application/x-x509-ca-cert\n\n";
    print $content;
  } elsif ($operation eq "PKIOperation") {
    my $decoded = $ca->scep_decode("ca1", $operation, $message);
    $decoded =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $decoded = $1;
    my $parser = XML::Simple->new();
    my $response = $parser->XMLin($decoded);

    # one time pin
    my $pin = $response->{'PKCS10'}->{'ChallengePassword'}->{'Password'} ;
    # IP Address
    my $key = $ENV{'REMOTE_ADDR'};

    # check PIN
    if (1) {
      my $pin_store = PKI::Base::PinStore->new();
      $pin_store->open($cfg);
      my $pinref = $pin_store->read_pin($key);
      if (defined($pinref) && $pinref->{'pin'} eq $pin) {
        $pin_store->delete($key);
      } else {
        $pin_store->close();
        # XXX - return SCEP error
        print $q->redirect("/ee/scep/installer.cgi");
        return;
      }
      $pin_store->close();
    }

    my $content = $ca->scep_pki_message("ca1", $operation, $message);

    print "Content-Type: application/x-pki-message\n\n";
    print $content;
  }
  $ca->close();
}

my $op = op->new();
$op->execute();
