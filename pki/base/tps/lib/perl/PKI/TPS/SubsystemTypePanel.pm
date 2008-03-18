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

use strict;
use warnings;
use PKI::TPS::GlobalVar;
use PKI::TPS::Common;

package PKI::TPS::SubsystemTypePanel;
$PKI::TPS::SubsystemTypePanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::TPS::Common::no;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(3);
    $self->{"getName"} = &PKI::TPS::Common::r("Subsystem Type");
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
    &PKI::TPS::Wizard::debug_log("SubsystemTypePanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("SubsystemTypePanel: update");
    $::symbol{systemname} = "Token Processing ";
    $::symbol{subsystemName} = "Token Processing System";
    $::symbol{fullsystemname} = "Token Processing System ";
    $::symbol{machineName} = "localhost";
    $::symbol{https_port} = "7889";
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
    &PKI::TPS::Wizard::debug_log("SubsystemTypePanel: display");
    $::symbol{systemname} = "Token Processing ";
    $::symbol{subsystemName} = "Token Processing System";
    $::symbol{fullsystemname} = "Token Processing System ";

    my $machineName = $::config->get("service.machineName");
    my $securePort = $::config->get("service.securePort");
    my $unsecurePort = $::config->get("service.unsecurePort");


    $::symbol{machineName} = $machineName;
    $::symbol{https_port} = $securePort;
    $::symbol{check_clonesubsystem} = "";
    $::symbol{check_newsubsystem} = "checked ";

    my $session_id = $q->param("session_id");
    $::config->put("preop.sessionID", $session_id);
    $::config->commit();

    $::symbol{urls}        = [];
    my $count = 0;
    while (1) {
      my $host = $::config->get("preop.securitydomain.tps$count.host");
      if ($host eq "") {
        goto DONE;
      }
      my $port = $::config->get("preop.securitydomain.tps$count.secureport");
      my $name = $::config->get("preop.securitydomain.tps$count.subsystemname");
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
