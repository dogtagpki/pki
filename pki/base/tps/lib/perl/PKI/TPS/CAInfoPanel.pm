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

package PKI::TPS::CAInfoPanel;
$PKI::TPS::CAInfoPanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

our $cert_header="-----BEGIN CERTIFICATE-----";
our $cert_footer="-----END CERTIFICATE-----";

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::TPS::Common::no;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(4);
    $self->{"getName"} = &PKI::TPS::Common::r("CA Information");
    $self->{"vmfile"} = "cainfopanel.vm";
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
    &PKI::TPS::Wizard::debug_log("CAInfoPanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("CAInfoPanel: update");

    my $count = $q->param('urls');
    &PKI::TPS::Wizard::debug_log("CAInfoPanel: update - got urls = $count");

    &PKI::TPS::Wizard::debug_log("CAInfoPanel: update - selected ca= $count");
    
    my $instanceID = $::config->get("service.instanceID");
    my $host = "";
    my $https_ee_port = "";

    if ($count =~ /http/) {
      my $info = new URI::URL($count);
      $host = $info->host;
      $https_ee_port = $info->port;
    } else {
      $host = $::config->get("preop.securitydomain.ca$count.host");
      $https_ee_port = $::config->get("preop.securitydomain.ca$count.secureport");
    }
    if (($host eq "") || ($https_ee_port eq "")) {
      $::symbol{errorString} = "no CA found.  CA, TKS and optionally DRM must be installed prior to TPS installation";
      return 0;
    }

    &PKI::TPS::Wizard::debug_log("CAInfoPanel: update - host= $host, https_ee_port= $https_ee_port");

    $::config->put("preop.cainfo.select", "https://$host:$https_ee_port");
    my $serverCertNickName = $::config->get("preop.cert.sslserver.nickname");

    my $subsystemCertNickName = $::config->get("preop.cert.subsystem.nickname");
    $::config->put("conn.ca1.clientNickname", $subsystemCertNickName);
    $::config->put("conn.ca1.hostport", $host . ":" . $https_ee_port);

    $::config->commit();

    # connect to the CA, and retrieve the CA certificate
    &PKI::TPS::Wizard::debug_log("CAInfoPanel: update connecting to CA and retrieve cert chain");
    my $instanceDir = $::config->get("service.instanceDir");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;
    my $tmpfile = "/tmp/ca-$$";
    system("/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$serverCertNickName\" -r \"/ca/ee/ca/getCertChain\" $host:$https_ee_port > $tmpfile");
    my $cmd = `cat $tmpfile`;
    system("rm $tmpfile");
    my $caCert;
    if ($cmd =~ /\<ChainBase64\>(.*)\<\/ChainBase64\>/) {
        $caCert =  $1;
        &PKI::TPS::Wizard::debug_log("CAInfoPanel: ca= $caCert");
    }
    if ($caCert eq "") {
        &PKI::TPS::Wizard::debug_log("CAInfoPanel: update no cert chain found");
        return 0;
    }
    open(F, ">$instanceDir/conf/caCertChain2.txt");
    print F $cert_header."\n".$caCert."\n".$cert_footer;
    close(F);

    &PKI::TPS::Wizard::debug_log("CAInfoPanel: update retrieve cert chain done");

    #import cert chain
    system("p7tool -d $instanceDir/alias -p $instanceDir/conf/chain2cert -a -i $instanceDir/conf/caCertChain2.txt -o $instanceDir/conf/CAchain2_pp.txt");
        my $r =  $? >> 8;
    my $failed = $? & 127;
    if (($r > 0) && ($r < 10) && !$failed)  {
        my $i = 0;
        while ($i ne $r) {
          my $tmp = `certutil -d $instanceDir/alias -D -n "Trusted CA c2cert$i"`;
          $tmp = `certutil -d $instanceDir/alias -A -f $instanceDir/conf/.pwfile -n "Trusted CA c2cert$i"  -t "CT,C,C" -i $instanceDir/conf/chain2cert$i.der`;
          $i++;
        }
    }

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("CAInfoPanel: display");

    $::symbol{urls}        = [];
#    unshift(@{$::symbol{urls}}, "External CA");
    my $count = 0;
    my $first = 1;
    my $list = "";
    while (1) {
      my $host = $::config->get("preop.securitydomain.ca$count.host");
      if ($host eq "") {
        goto DONE;
      }
      my $https_ee_port = $::config->get("preop.securitydomain.ca$count.secureport");
      my $name = $::config->get("preop.securitydomain.ca$count.subsystemname");
      my $item = $name . " - https://" . $host . ":" . $https_ee_port;
#      my $item = "https://" . $host . ":" . $https_ee_port;
#      unshift(@{$::symbol{urls}}, $item);
      $::symbol{urls}[$count++] = $item;
      if ($first eq 1) {
          $list = $item;
          $first = 0;
      } else {
          $list = $list.",".$item;
      }
    }
DONE:
#    $list = $list.",External CA";
    $::config->put("preop.ca.list", $list);
    
    $::symbol{urls_size}   = $count;
    if ($count eq 0) {
      $::symbol{errorString} = "no CA found. CA, TKS, and optionally DRM must be installed prior to TPS installation";
      return 0;
    }
    return 1;
}

1;
