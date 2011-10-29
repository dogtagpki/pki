#!/usr/bin/perl
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
use URI::URL;

package PKI::TPS::ImportAdminCertPanel;
$PKI::TPS::ImportAdminCertPanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&is_panel_done;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(15);
    $self->{"getName"} = &PKI::TPS::Common::r("Import Administrator Certificate");
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
    &PKI::TPS::Wizard::debug_log("ImportAdminCertPanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("ImportAdminCertPanel: update");

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
    my $tokenname = $::config->get("preop.module.token");
    my $token_pwd = $::pwdconf->get($tokenname);
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    my $name = $subsystemName;
    my $subCertNickName = $::config->get("preop.cert.subsystem.nickname");

    $db_password =~ s/\n$//g;

    my $params = "list=" . "TPSList" . "&" .
                 "type=" . "TPS" . "&" .
                 "host=" . $machineName . "&" .
                 "name=" . $name . "&" .
                 "sport=" . $securePort . "&" .
                 "dm=false"; # domain manager or not

    my $sd_host =  $sdom_url->host;
    my $sd_agent_port = $sdom_url->port;
    my $cmd;
    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        $cmd = `/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$subCertNickName\" -r \"/ca/agent/ca/updateDomainXML\" -e \"$params\" $sd_host:$sd_agent_port`;
    } else {
        $cmd = `/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$token_pwd\" -v -n \"$subCertNickName\" -r \"/ca/agent/ca/updateDomainXML\" -e \"$params\" $sd_host:$sd_agent_port`;
    }

    # Fetch the "updated" security domain and display it 
    &PKI::TPS::Wizard::debug_log("ImportAdminCertPanel:  Dump contents of updated Security Domain . . .");
    my $sdomainAdminURL = $::config->get("config.sdomainAdminURL");
    my $sdom_info = new URI::URL($sdomainAdminURL);
    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    $sd_host = $sdom_info->host;
    my $sd_admin_port = $sdom_info->port;
    my $content;
    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        $content = `/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$db_password\" -v -r \"/ca/admin/ca/getDomainXML\" $sd_host:$sd_admin_port`;
    } else {
        $content = `/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$token_pwd\" -v -r \"/ca/admin/ca/getDomainXML\" $sd_host:$sd_admin_port`;
    }
    $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $content = $1;
    &PKI::TPS::Wizard::debug_log($content);

    $::config->put("preop.importadmincert.done", "true");
    $::config->commit();

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("ImportAdminCertPanel: display");

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

sub is_panel_done
{
   return $::config->get("preop.importadmincert.done");
}

1;
