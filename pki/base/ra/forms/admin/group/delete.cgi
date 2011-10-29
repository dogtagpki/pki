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
  $store->delete_group($gid);
  $store->close();

  print $q->redirect("/admin/group/index.cgi");
}

my $op = op->new();
$op->execute();
