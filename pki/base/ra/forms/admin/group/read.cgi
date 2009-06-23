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

  my $util = PKI::Base::Util->new();

  my $docroot = PKI::Base::Registry->get_docroot();
  my $parser = PKI::Base::Registry->get_parser();
  my $cfg = PKI::Base::Registry->get_config();

  $self->debug_params($cfg, $q);

  if (!$self->admin_auth($cfg)) {
    print $q->redirect("/admin/error.cgi");
    return;
  }
  my $uid = $self->get_current_uid($cfg);

  my %context;
  $context{uid} = $util->html_encode($uid);

  my $gid = $util->get_val($q->param('gid'));

  my $store = PKI::Base::UserStore->new();
  $store->open($cfg);
  my $ref = $store->read_group($gid);

  $context{gid} = $util->html_encode(Encode::decode('UTF-8', $ref->{'gid'}));
  $context{name} = $util->html_encode(Encode::decode('UTF-8', $ref->{'name'}));

  my @members = $store->list_all_members($gid);
  my @users = $store->list_all_non_members($gid);
  $store->close();

  # new member in the group
  my @r;
  my $i = 0;
  foreach my $member (@members) {
    $r[$i] = new PKI::RA::GlobalVar(
                    getUID => sub { return $util->html_encode($member->{'uid'}) },
                   );
    $i++;
  }
  $context{members} = \@r;

  # read users
  my @u;
  $i = 0;
  foreach my $user (@users) {
    $u[$i] = new PKI::RA::GlobalVar(
                    getUID => sub { return $util->html_encode($user->{'uid'}) },
                   );
    $i++;
  }
  if ($i == 0) {
    $context{non_member_exists} = 0;
  } else {
    $context{non_member_exists} = 1;
  }
  $context{users} = \@u;

  my $result = $parser->execute_file_with_context("admin/group/read.vm",
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
