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

package PKI::TPS::LoginPanel;
$PKI::TPS::LoginPanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::TPS::Common::no;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(0);
    $self->{"getName"} = &PKI::TPS::Common::r("Welcome");
    $self->{"vmfile"} = "login.vm";
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
    &PKI::TPS::Wizard::debug_log("WelcomePanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("WelcomePanel: update");
    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log($ENV{'SERVER_PORT'});
    &PKI::TPS::Wizard::debug_log("Debug=" . $::config->get("logging.debug.enable"));
    &PKI::TPS::Wizard::debug_log("WelcomePanel: display");
    $::symbol{wizardname}  = "TPS Configuration Wizard";
    $::symbol{systemname}  = "TPS";
    $::symbol{fullsystemname}  = "Token Processing System";

    return 1;
}

1;
