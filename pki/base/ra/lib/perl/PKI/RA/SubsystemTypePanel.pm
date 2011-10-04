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

package PKI::RA::SubsystemTypePanel;
$PKI::RA::SubsystemTypePanel::VERSION = '1.00';

use PKI::RA::BasePanel;
our @ISA = qw(PKI::RA::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::RA::Common::no;
    $self->{"getPanelNo"} = &PKI::RA::Common::r(3);
    $self->{"getName"} = &PKI::RA::Common::r("Subsystem Type");
    $self->{"vmfile"} = "createsubsystempanel.vm";
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
    &PKI::RA::Wizard::debug_log("SubsystemTypePanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("SubsystemTypePanel: update");
    $::symbol{systemname} = "Registration Authority ";
    $::symbol{subsystemName} = "Registration Authority";
    $::symbol{fullsystemname} = "Registration Authority";
    $::symbol{machineName} = "localhost";
    $::symbol{http_port} = "12888";
    $::symbol{https_port} = "12889";
    $::symbol{non_clientauth_https_port} = "12890";
    $::symbol{check_clonesubsystem} = " ";
    $::symbol{check_newsubsystem} = " ";
    $::symbol{disableClone} = 1;

    my $subsystemName = $q->param('subsystemName');
    $::config->put("preop.subsystem.name", $subsystemName);
    $::config->commit();

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("SubsystemTypePanel: display");
    $::symbol{systemname} = "Registration Authority ";
    $::symbol{subsystemName} = "Registration Authority";
    $::symbol{fullsystemname} = "Registration Authority ";

    my $machineName = $::config->get("service.machineName");
    my $unsecurePort = $::config->get("service.unsecurePort");
    my $securePort = $::config->get("service.securePort");
    my $non_clientauth_securePort = $::config->get("service.non_clientauth_securePort");


    $::symbol{machineName} = $machineName;
    $::symbol{http_port} = $unsecurePort;
    $::symbol{https_port} = $securePort;
    $::symbol{non_clientauth_https_port} = $non_clientauth_securePort;
    $::symbol{check_clonesubsystem} = "";
    $::symbol{check_newsubsystem} = "checked ";

    my $session_id = $q->param("session_id");
    $::config->put("preop.sessionID", $session_id);
    $::config->commit();

    $::symbol{urls}        = [];
    my $count = 0;
    while (1) {
      my $host = $::config->get("preop.securitydomain.ra$count.host");
      if ($host eq "") {
        goto DONE;
      }
      my $port = $::config->get("preop.securitydomain.ra$count.non_clientauth_secure_port");
      my $name = $::config->get("preop.securitydomain.ra$count.subsystemname");
      unshift(@{$::symbol{urls}}, "https://" . $host . ":" . $port);
      $count++;
    }
DONE:
    $::symbol{urls_size}   = $count;

#    if ($count == 0) {
      $::symbol{disableClone} = 1;
#    }

    # XXX - how to deal with urls
    return 1;
}


1;
