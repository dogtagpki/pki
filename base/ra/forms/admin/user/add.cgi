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
  $context{uid} = $uid;

  my $userid = $util->get_val($q->param('uid'));
  my $name = $util->get_val($q->param('name'));
  my $email = $util->get_val($q->param('email'));
  my $certificate = $util->get_val($q->param('certificate'));

  if ($certificate =~ /BEGIN CERTIFICATE/ || 
        $certificate =~ /END CERTIFICATE/) {
     # do nothing
  } else { 
    print $q->redirect("/admin/user/add_new.cgi?error=cert_header");
    return;
  }
  $certificate =~ s/-----BEGIN CERTIFICATE-----//g;
  $certificate =~ s/-----END CERTIFICATE-----//g;
  $certificate =~ s/[\r\n]//g;

  my $store = PKI::Base::UserStore->new();
  $store->open($cfg);
  my $ref = $store->read_user($userid);
  if (defined($ref)) {
    # uid used
    print $q->redirect("/admin/user/add_new.cgi?error=exist");
    return;
  }
  my $ref = $store->add_user($userid, $name, $email, $certificate);
  $store->close();

  print $q->redirect("/admin/user/index.cgi");
}

my $op = op->new();
$op->execute();
