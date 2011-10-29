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
package PKI::Base::TimeTool;

use Time::Local;

use DBI;
use PKI::Base::TimeTool;

#######################################
# Constructs a request queue
#######################################
sub new {
  my $self = {};
  bless ($self);
  return $self;
}

sub get_time()
{
  my ($self) = @_;
  my ($sec, $min, $hr, $mday, $mnth, $y, $wd, $yd, $ds) = localtime();
  my $r_year = 1900 + $y;
  my $r_mnth;
  my $r_day;
  $r_day = $mday;
  $mnth = $mnth + 1;
  $r_mnth = $mnth;
  return "$r_year-$r_mnth-$r_day $hr:$min:$sec";
}


1;
