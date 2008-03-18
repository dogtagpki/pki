#!/usr/bin/pkiperl
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

package PKI::Base::Conf;

use strict;
use warnings;
use Exporter;

$PKI::Base::Conf::VERSION = '1.00';

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

sub commit
{
    my ($self) = @_;

    # write stuff back to the file
#    print $self->{filename} . "\n";
    my $hash = $self->{hash};
    my $suffix = time();

    if (-e $self->{filename}) {
      system("mv \"" . $self->{filename} . "\" \"" . 
          $self->{filename} . "." . $suffix . "\"");
    }

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
    system("mv \"" . $self->{filename} . "\" \"" . 
          $self->{filename} . "." . $suffix . "\"");

    open(F, ">" . $self->{filename});
    foreach my $k (sort keys %{$hash}) {
         print F "$k=$self->{hash}{$k}\n";
    }
    close(F);
}

1;
