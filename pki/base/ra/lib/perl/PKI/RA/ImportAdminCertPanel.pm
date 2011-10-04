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
use URI::URL;

package PKI::RA::ImportAdminCertPanel;
$PKI::RA::ImportAdminCertPanel::VERSION = '1.00';

use PKI::RA::BasePanel;
our @ISA = qw(PKI::RA::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::RA::Common::no;
    $self->{"getPanelNo"} = &PKI::RA::Common::r(15);
    $self->{"getName"} = &PKI::RA::Common::r("Import Administrator Certificate");
    $self->{"vmfile"} = "importadmincertpanel.vm";
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
    &PKI::RA::Wizard::debug_log("ImportAdminCertPanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("ImportAdminCertPanel: update");

    # register to Security Domain
    my $sdom = $::config->get("config.sdomainAgentURL");
    my $sdom_url = new URI::URL($sdom);

    #
    # we need to authenticate to the security domain with the subsystem
    # certificate
    #
    my $machineName = $::config->get("service.machineName");
    my $instanceID = $::config->get("service.instanceID");
    my $instanceDir = $::config->get("service.instanceDir");
    my $securePort = $::config->get("service.securePort");
    my $subsystemName = $::config->get("preop.subsystem.name");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    my $name = $subsystemName;
    my $subCertNickName = $::config->get("preop.cert.subsystem.nickname");

    $db_password =~ s/\n$//g;

    my $params = "list=" . "RAList" . "&" .
                 "type=" . "RA" . "&" .
                 "host=" . $machineName . "&" .
                 "name=" . $name . "&" .
                 "sport=" . $securePort . "&" .
                 "dm=false"; # domain manager or not

    my $cmd = `/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$subCertNickName\" -r \"/ca/agent/ca/updateDomainXML?$params\" $sdom_url->host:$sdom_url->port`;

    # Fetch the "updated" security domain and display it
    &PKI::RA::Wizard::debug_log("ImportAdminCertPanel:  Dump contents of updated Security Domain . . .");
    my $sdomainAdminURL = $::config->get("config.sdomainAdminURL");
    my $sdom_info = new URI::URL($sdomainAdminURL);
    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    my $sd_host = $sdom_info->host;
    my $sd_admin_port = $sdom_info->port;
    my $content = `/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$nickname\" -r \"/ca/admin/ca/getDomainXML\" $sd_host:$sd_admin_port`;
    $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $content = $1; 
    &PKI::RA::Wizard::debug_log($content);

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("ImportAdminCertPanel: display");

    my $cainfo = $::config->get("preop.cainfo.select");

    my $cainfo_url = new URI::URL($cainfo);
    my $serialNumber = $::config->get("preop.admincert.serialno.0");

    $::symbol{info} = "";
    $::symbol{errorString} = "";
    $::symbol{import} = "true";
    $::symbol{ca} = "false";
    $::symbol{caType} = "ca";
    $::symbol{caHost} = $cainfo_url->host;
    $::symbol{caPort} = $cainfo_url->port;
    $::symbol{serialNumber} = $serialNumber;

    return 1;
}

1;
