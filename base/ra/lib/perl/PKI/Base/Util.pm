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
package PKI::Base::Util;

use Time::Local;

use DBI;
use HTML::Entities;

#######################################
# Constructs a util
#######################################
sub new {
  my $self = {};
  bless ($self);
  return $self;
}

sub get_val()
{
  my ($self, $s) = @_;
  return $s;
}

sub get_integer_val()
{
  my ($self, $s) = @_;
  return $s;
}

sub get_string_val()
{
  my ($self, $s) = @_;
  return $s;
}

sub get_alphanum_val()
{ 
  my ($self, $s) = @_;
  $s =~ s/[^A-Za-z0-9 ]*//g;
  return $s;
}

sub normalize_csr()
{
  my ($self, $s) = @_;
  $s =~ s/-----BEGIN CERTIFICATE REQUEST-----//g;
  $s =~ s/-----END CERTIFICATE REQUEST-----//g;
  $s =~ s/-----BEGIN NEW CERTIFICATE REQUEST-----//g;
  $s =~ s/-----END NEW CERTIFICATE REQUEST-----//g;
  $s =~ s/\s//g;
  return $s;
}

sub breakline()
{
  my ($self, $s, $maxlen) = @_;

  my $new_s;
  my $i = 0;
  foreach my $c (split(//, $s)) {
    if ($i == $maxlen) {
       $i = 0;
       $new_s = $new_s . "<br/>";
    }
    $new_s = $new_s . $c;
    $i++;
  }
  return $new_s;
}

sub nv_to_hash()
{
  my ($self, $s) = @_;
  my %hash;
  my @pairs = split(/;/, $s);
  foreach $pair (@pairs) {
    my $i = index('=', $pair);
    my $n = substr($pair, 0, $i-1);
    my $v = substr($pair, $i);
    $hash{$n} = $v;
  }
  return \%hash;
}

sub nv_to_str()
{
  my ($self, $hash) = @_;
  my $s = "";
  foreach $k (keys %$hash) {
    if ($s eq "") {
      $s = $k . "=" . $$hash{$k};
    } else {
      $s = $s . ";" . $k . "=" . $$hash{$k};
    }
  }
  return $s;
}

sub test() 
{
  my %h;
  $h{'x'} = 'y';
  $h{'z'} = 'y';
  my $o = PKI::Base::NameValueUtil->new();
  print $o->to_str(\%h) . "\n";
  print $o->to_str($o->to_hash("5=1;c=2")) . "\n";
}

sub html_encode()
{
  my ($self, $s) = @_;
  return HTML::Entities::encode($s);
}

sub html_encode_and_break()
{
  my ($self, $s, $maxlen) = @_;
  my $new_s = '';
  my $i = 0;
  foreach my $c (split(//, $s)) {
    if ($i == $maxlen) {
       $i = 0;
       $new_s = $new_s . '***';
    }
    $new_s = $new_s . $c;
    $i++;
  }
  $s = HTML::Entities::encode($new_s);
  $s =~ s/\*\*\*/<br\/>/g;
  return $s;
}

1;
