#!/usr/bin/pkiperl
#
# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301  USA 
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#

package PKI::TPS::Config;

use strict;
use warnings;
use Exporter;

$PKI::TPS::Config::VERSION = '1.00';

#######################################################
# Configuration Store
#######################################################
sub new {
    my $class = shift;
    my $self = {};
    my %hash = ();
    $self->{filename} = "";
    $self->{hash} = \%hash;
    bless $self,$class;
    return $self;
}

sub load_file
{
    my ($self, $filename) = @_;

    $self->{filename} = $filename;
    if (-e $filename) {
      open(CF, "<$filename");
      if (defined fileno CF) {
        while (<CF>) {
          if (/^#/) {
            # comments
          } elsif (/([^=]+)=(.*)$/) {
            # print "$1 = $2\n";
            $self->{hash}{$1} = $2;
          } else {
            # preserve comments
          }  
        }
      }
      close(CF);
    }
}

sub get_filename
{
    my ($self) = @_;
    return $self->{filename};
}

sub get
{
    my ($self, $n) = @_;
    return $self->{hash}{$n};
}

sub put
{
    my ($self, $n, $v) = @_;
    $self->{hash}{$n} = $v;
}

sub deleteSubstore
{
    my ($self, $n) = @_;
    foreach my $xkey (keys %{$self->{hash}}) {
        if ($xkey =~ /^\Q$n\E/) {
            delete $self->{hash}{$xkey};
        }
    } 
}

sub commit
{
    my ($self) = @_;

    # write stuff back to the file
#    print $self->{filename} . "\n";
    my $hash = $self->{hash};
    my $suffix = time();

    if (-e $self->{filename}) {
      # Create a copy of the original file which
      # preserves the original file permissions
      system("cp -p \"" . $self->{filename} . "\" \"" .
          $self->{filename} . "." . $suffix . "\"");
    }

    # Overwrite the contents of the original file
    # to preserve the original file permissions
    open(F, ">" . $self->{filename});
    foreach my $k (sort keys %{$hash}) {
         print F "$k=$self->{hash}{$k}\n";
    }
    close(F);

    if (-e $self->{filename} . "." . $suffix) {
      system("rm \"" . $self->{filename} . "." . $suffix . "\"");
    }
}

sub commit_with_backup
{
    my ($self) = @_;

    # write stuff back to the file
#    print $self->{filename} . "\n";
    my $hash = $self->{hash};
    my $suffix = time();
    # Create a copy of the original file which
    # preserves the original file permissions
    system("cp -p \"" . $self->{filename} . "\" \"" . 
          $self->{filename} . "." . $suffix . "\"");

    # Overwrite the contents of the original file
    # to preserve the original file permissions
    open(F, ">" . $self->{filename});
    foreach my $k (sort keys %{$hash}) {
         print F "$k=$self->{hash}{$k}\n";
    }
    close(F);
}

1;

#######################################################
# Test Program
#######################################################
#my $config = PKI::TPS::Config->new();
#$config->load_file("/tmp/CS.cfg");
#print $config->get("tokendb.indexAdminTemplate") . "\n";
#$config->put("tokendb.indexAdminTemplate", "Testing");
#print $config->get("tokendb.indexAdminTemplate") . "\n";
#$config->commit();

1;

#######################################################
# Test Program
#######################################################
#my $config = PKI::TPS::Config->new();
#$config->load_file("/tmp/CS.cfg");
#print $config->get("tokendb.indexAdminTemplate") . "\n";
#$config->put("tokendb.indexAdminTemplate", "Testing");
#print $config->get("tokendb.indexAdminTemplate") . "\n";
#$config->commit();
