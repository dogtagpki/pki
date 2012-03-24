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
use PKI::Request::Queue;
use PKI::Base::Registry;
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

  my $docroot = PKI::Base::Registry->get_docroot();
  my $parser = PKI::Base::Registry->get_parser();
  my $cfg = PKI::Base::Registry->get_config();

  my $util = PKI::Base::Util->new();

  $self->debug_params($cfg, $q);

  if (!$self->admin_auth($cfg)) {
    print $q->redirect("/admin/error.cgi");
    return;
  }
  my $uid = $self->get_current_uid($cfg);

  my %context;
  $context{uid} = $uid;

  my $status = $util->get_alphanum_val($q->param('status'));
  $context{status} = $status;

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

  my $store = PKI::Base::UserStore->new();
  $store->open($cfg);
  my @users = $store->list_users($sp, $mc);
  $store->close();

  my @r;
  my $i = 0;
  foreach my $user (@users) {
    $r[$i] = new PKI::RA::GlobalVar(
                    getUID => sub { return $util->html_encode($user->{'uid'}) },
                    getName => sub { return $util->html_encode(Encode::decode('UTF-8',$user->{'name'})) },
                    getEmail => sub { return $util->html_encode($user->{'email'}) },
                   );
    $i++;
  }
  $context{rows} = \@r;

  my $result = $parser->execute_file_with_context("admin/user/index.vm",
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
