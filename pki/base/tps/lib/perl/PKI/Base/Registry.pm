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
package PKI::Base::Registry;

use PKI::Base::Conf;

my $docroot;
my $cfg;
my $parser;

BEGIN {
  $docroot = $ENV{DOCUMENT_ROOT};
  $cfg = PKI::Base::Conf->new();
  $cfg->load_file("$docroot/../conf/CS.cfg");
  $parser = new Template::Velocity($docroot);

}

sub get_docroot {
  my ($self) = @_;
  return $docroot;
}

sub get_parser {
  my ($self) = @_;
  return $parser;
}

sub get_config {
  my ($self) = @_;
  return $cfg;
}

1;
