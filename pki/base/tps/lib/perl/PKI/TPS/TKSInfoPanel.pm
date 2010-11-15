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

package PKI::TPS::TKSInfoPanel;
$PKI::TPS::TKSInfoPanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&is_panel_done;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(5);
    $self->{"getName"} = &PKI::TPS::Common::r("TKS Information");
    $self->{"vmfile"} = "tksinfopanel.vm";
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
    &PKI::TPS::Wizard::debug_log("TKSInfoPanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("TKSInfoPanel: update");

    my $count = $q->param('urls') || "";
    if ($count eq "") {
        $::symbol{errorString} = "no TKS info provided.  CA, TKS and optionally DRM must be installed prior to TPS installation";
        return 0;
    }
    &PKI::TPS::Wizard::debug_log("TKSInfoPanel: update - got urls = $count");

    my $instanceID = $::config->get("service.instanceID");
    my $host = "";
    my $https_agent_port = "";
    my $https_admin_port = "";

    if ($count =~ /http/) {
      # this is for pkisilent
      my $info = new URI::URL($count);
      $host = $info->host || "";
      $https_agent_port = $info->port || "";
      $https_admin_port = q->param('adminport') || "";
    } else {
      $host = $::config->get("preop.securitydomain.tks$count.host") || "";
      $https_admin_port = $::config->get("preop.securitydomain.tks$count.secureadminport") || "";
      $https_agent_port = $::config->get("preop.securitydomain.tks$count.secureagentport") || "";
    }

    if (($host eq "") || ($https_agent_port eq "")) {
      $::symbol{errorString} = "no TKS found.  CA, TKS and optionally DRM must be installed prior to TPS installation";
      return 0;
    }

    if ($https_admin_port eq "") {
      if ($count =~ /http/) {
        $::symbol{errorString} = "TKS admin port must be provided";
      } else {
        $::symbol{errorString} = "TKS admin port not provided by security domain.";
      } 
      return 0;
    }

    my $subsystemCertNickName = $::config->get("preop.cert.subsystem.nickname");
    $::config->put("preop.tksinfo.select", "https://$host:$https_admin_port");
    $::config->put("conn.tks1.clientNickname", $subsystemCertNickName);
    $::config->put("conn.tks1.hostport", $host . ":" . $https_agent_port); 
    $::config->put("preop.tksinfo.done", "true");
    $::config->commit();

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("TKSInfoPanel: display");
    $::symbol{urls}        = [];
    my $count = 0;
    while (1) {
      my $host = "";
      $host = $::config->get("preop.securitydomain.tks$count.host");
      if ($host eq "") {
        goto DONE;
      }
      my $https_agent_port = $::config->get("preop.securitydomain.tks$count.secureagentport");
      my $name = $::config->get("preop.securitydomain.tks$count.subsystemname");
      $::symbol{urls}[$count++] = $name . " - https://" . $host . ":" . $https_agent_port;
    }
DONE:
    $::symbol{urls_size}   = $count;
    if ($count eq 0) {
      $::symbol{errorString} = "no TKS found.  CA, TKS and optionally DRM must be installed prior to TPS installation";
      return 0;
    }

    return 1;
}

sub is_panel_done
{
   return $::config->get("preop.tksinfo.done");
}


1;
