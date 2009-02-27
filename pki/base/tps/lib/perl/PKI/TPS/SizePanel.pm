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
use PKI::TPS::CertInfo;

package PKI::TPS::SizePanel;
$PKI::TPS::SizePanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::TPS::Common::no;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(11);
    $self->{"getName"} = &PKI::TPS::Common::r("Key Pairs");
    $self->{"vmfile"} = "sizepanel.vm";
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
    &PKI::TPS::Wizard::debug_log("SizePanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("SizePanel: update");

    my $instanceDir = $::config->get("service.instanceDir");
    my $done = $::config->get("preop.SizePanel.done");
    my $genKeyPair = $q->param('generateKeyPair');
    &PKI::TPS::Wizard::debug_log("SizePanel: update generateKeyPair value=$genKeyPair");
    if ($done eq "true") {
        if ($genKeyPair eq "") {
            &PKI::TPS::Wizard::debug_log("SizePanel: update generateKeyPair value not found, turn to off");
            $genKeyPair = "off";
        }
    } else {
        # firstime should always generate keys
        $genKeyPair = "on";
    }

    foreach my $certtag (@PKI::TPS::Wizard::certtags) { 
        my $select = $q->param($certtag.'_choice');
        my $keytype = $q->param($certtag.'_keytype');
        my $size = $q->param($certtag.'_custom_size');

        &PKI::TPS::Wizard::debug_log("SizePanel: update $certtag _choice=$select $certtag _keytype=$keytype customsize= $size");

        $::config->put("preop.keysize.select", $select);
        $::config->put("preop.cert.".$certtag.".keysize.select", $select);

        if (! isSupportedSize($keytype, $size)) {
            &PKI::TPS::Wizard::debug_log("SizePanel: update size $size not supported");
            return 0;
        }
        $::config->put("preop.cert.".$certtag.".keysize.customsize", $size);
            $::config->put("preop.cert.".$certtag.".keytype", $keytype);

        if ($select eq "default") {
            my $defaultSize = getDefaultSize($keytype);
            &PKI::TPS::Wizard::debug_log("SizePanel: update in default, defaultsize = $defaultSize");
            $::config->put("preop.keysize.customsize", $defaultSize);
            $::config->put("preop.keysize.size", $defaultSize);
            $::config->put("preop.cert.".$certtag.".keysize.size", $defaultSize);

        } elsif ($select eq "custom") {
            &PKI::TPS::Wizard::debug_log("SizePanel: update in custom, customsize = $size");
            $::config->put("preop.keysize.size", $size);
            $::config->put("preop.cert.".$certtag.".keysize.size", $size);
        }

        if ($genKeyPair eq "on") {
            $::config->put("preop.cert.".$certtag.".certreq", "");
            $::config->put("preop.cert.".$certtag.".cert", "");
        }
    }
#XXX should have better error checking to work better
    $done = $::config->put("preop.SizePanel.done", "true");
    $::config->commit();

    return 1;
}

sub getDefaultSize {
    my $keytype = $_[0];

    if ($keytype eq "ecc") {
        return 256;
    } elsif ($keytype eq "rsa") {
        return 2048;
    }

    $::symbol{errorString} = "Unsupported keytype $keytype";
    return 0;
}

sub isSupportedSize {
    my $keytype = $_[0];
    my $size = $_[1];

    if (($keytype eq "ecc") && ($size ne "256")) {
        &PKI::TPS::Wizard::debug_log("SizePanel: isSupportedSize ECC only supports size 256");
        $::symbol{errorString} = "Unsupported Size $size. ECC only supports size 256";
        return 0;
    }

    if (($size eq "256") || ($size eq "512") || ($size eq "1024") ||
        ($size eq "2048") || ($size eq "4096")) {
        return 1;
    }
    # wrong size
    $::symbol{errorString} = "Unsupported Size $size. RSA only supports sizes 256, 512, 1024, 2048, and 4096";
    return 0;
}

sub display
{
    my ($q) = @_;

    &PKI::TPS::Wizard::debug_log("SizePanel: display");

    my $done = $::config->get("preop.SizePanel.done");
    &PKI::TPS::Wizard::debug_log("SizePanel: display is panel done? $done");
    if ($done eq "true") {
        $::symbol{firsttime} = "false";
    } else {
        $::symbol{firsttime} = "true";
    } 

    my $domain_name = $::config->get("preop.securitydomain.name");
    if ($domain_name eq "") {
        $domain_name = "TPS Domain";
    }

    my $machine_name =  $::config->get("service.machineName");
    my $instance_id = $::config->get("service.instanceID");

    my $i = 0;
    foreach my $certtag (@PKI::TPS::Wizard::certtags) { 
        my $cert_dn = $::config->get("preop.cert.".$certtag.".dn");
        if ($cert_dn eq "") {
            if ($certtag eq "subsystem") {
                $cert_dn = "CN=TPS Subsystem, " .
                  "OU=" . $instance_id . ", " .
                  "O=" . $domain_name;
            } elsif ($certtag eq "sslserver") {
                $cert_dn ="CN=" . $machine_name . ", " .
                  "OU=" . $instance_id . ", " .
                  "O=" . $domain_name;
            } else {
                $cert_dn = $certtag;
            }
        }
        my $name = $::config->get("preop.cert.".$certtag.".userfriendlyname");
        if ($name eq "") {
            $name = $certtag."Cert ".$instance_id;
        }
        my $cert = new PKI::TPS::CertInfo($name,
                  $cert_dn, $certtag);
        $::symbol{certs}[$i++] = $cert;
    }

    #for "common key settings"
    my $select = $::config->get("preop.keysize.select");
    if ($select ne "") {
        &PKI::TPS::Wizard::debug_log("SizePanel: display keysize select= $select");
        $::symbol{select} = $select;
    } else {
        $::symbol{select} = "default";
    }
    my $default_size = $::config->get("preop.keysize.size");
    if ($default_size eq "") {
        $::symbol{default_keysize} = 2048;
    } else {
        $::symbol{default_keysize} = $default_size;
    }
    my $default_ecc_size =  $::config->get("preop.keysize.ecc.size");
    if ($default_ecc_size eq "") {
        $::symbol{default_ecc_keysize} = 256;
    } else {
        $::symbol{default_ecc_keysize} = $default_ecc_size;
    }

    my $custom_size = $::config->get("preop.keysize.customsize");
    if ($custom_size eq "") {
        $::symbol{custom_size} = 2048;
    } else {
        $::symbol{custom_size} = $default_size;
    }


    return 1;
}

1;
