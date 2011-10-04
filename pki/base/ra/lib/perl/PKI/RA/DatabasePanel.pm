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

use strict;
use warnings;
use PKI::RA::GlobalVar;
use PKI::RA::Common;

use DBI;
package PKI::RA::DatabasePanel;
$PKI::RA::DatabasePanel::VERSION = '1.00';

use PKI::RA::BasePanel;
our @ISA = qw(PKI::RA::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::RA::Common::no;
    $self->{"getPanelNo"} = &PKI::RA::Common::r(8);
    $self->{"getName"} = &PKI::RA::Common::r("Internal Database");
    $self->{"vmfile"} = "databasepanel.vm";
    $self->{"update"} = \&update;
    $self->{"panelvars"} = \&display;
    bless $self,$class; 
    return $self; 
}

sub is_sub_panel
{
    my ($q) = @_;
    return 0;
}

sub has_sub_panel
{
    my ($q) = @_;
    return 0;
}

sub validate
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DatabasePanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DatabasePanel: update");
    my $instDir =  $::config->get("service.instanceDir");

    # create local database
    my $dbh = DBI->connect(
                "dbi:SQLite:dbname=$instDir/conf/dbfile","","");

    # create database lockfile
    system("touch $instDir/conf/dblock");

    open(F, "/usr/share/pki/ra/scripts/schema.sql");
    while (<F>) {
      if (!($_ =~ /^#/)) {
        $dbh->do($_);
      }
    }
    close(F);

    $dbh->disconnect();

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DatabasePanel: display");

    my $machineName = $::config->get("service.machineName");
    my $instanceId =  $::config->get("service.instanceID");

    return 1;
}

1;
