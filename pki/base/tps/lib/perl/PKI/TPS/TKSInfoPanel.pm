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
    $self->{"isPanelDone"} = \&PKI::TPS::Common::no;
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

    my $count = $q->param('urls');

    my $instanceID = $::config->get("service.instanceID");

    my $host = "";
    my $port = "";
    if ($count =~ /http/) {
      my $info = new URI::URL($count);
      $host = $info->host;
      $port = $info->port;
      if (($host eq "") || ($port eq "")) {
        $::symbol{errorString} = "no TKS found.  CA, TKS and optionally DRM must be installed prior to TPS installation";
        return 0;
      }
      $::config->put("preop.tksinfo.select", $count);
    } else {
      $host = $::config->get("preop.securitydomain.tks$count.host");
      $port = $::config->get("preop.securitydomain.tks$count.secureport");
      if (($host eq "") || ($port eq "")) {
        $::symbol{errorString} = "no TKS found.  CA, TKS and optionally DRM must be installed prior to TPS installation";
        return 0;
      }
      $::config->put("preop.tksinfo.select", "https://$host:$port");
    }
    my $subsystemCertNickName = $::config->get("preop.cert.subsystem.nickname");
    $::config->put("conn.tks1.clientNickname", $subsystemCertNickName);
    $::config->put("conn.tks1.hostport", $host . ":" . $port); 
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
      my $host = $::config->get("preop.securitydomain.tks$count.host");
      if ($host eq "") {
        goto DONE;
      }
      my $port = $::config->get("preop.securitydomain.tks$count.secureport");
      my $name = $::config->get("preop.securitydomain.tks$count.subsystemname");
      $::symbol{urls}[$count++] = $name . " - https://" . $host . ":" . $port;
    }
DONE:
    $::symbol{urls_size}   = $count;
    if ($count eq 0) {
      $::symbol{errorString} = "no TKS found.  CA, TKS and optionally DRM must be installed prior to TPS installation";
      return 0;
    }

    return 1;
}

1;
