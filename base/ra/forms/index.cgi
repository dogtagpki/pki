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
use PKI::Service::Op;
use Template::Velocity;
use PKI::Base::Conf;
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

  my $docroot = PKI::Base::Registry->get_docroot();
  my $parser = PKI::Base::Registry->get_parser();
  my $cfg = PKI::Base::Registry->get_config();

  $self->debug_params($cfg, $q);

  $::symbol{machineName} = $cfg->get("service.machineName");
  $::symbol{non_clientauth_securePort} = $cfg->get("service.non_clientauth_securePort");
  $::symbol{securePort} = $cfg->get("service.securePort");
  $::symbol{unsecurePort} = $cfg->get("service.unsecurePort");

  my $result = $parser->execute_file("index.vm");

  my $xml = $q->param('xml');
  if ($xml eq "true") {
    print "Content-Type: text/xml\n\n";
    print $self->xml_output(\%::symbol);
  } else {
    print "Content-Type: text/html\n\n";
    print "$result";
  }
}


my $op = op->new();
$op->execute();
