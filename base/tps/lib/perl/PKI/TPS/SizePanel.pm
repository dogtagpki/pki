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
    $self->{"isPanelDone"} = \&is_panel_done;
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
    my $genKeyPair = $q->param('generateKeyPair') || "";
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
        my $defaultSize = getDefaultSize($keytype);

        &PKI::TPS::Wizard::debug_log("SizePanel: update $certtag _choice=$select $certtag _keytype=$keytype customsize= $size");

        $::config->put("preop.keysize.select", $select);
        $::config->put("preop.cert.".$certtag.".keysize.select", $select);

        # sizematch is for checking if it's supported
        my $sizematch = "";
        if ($select eq "default") {
            $sizematch = "$defaultSize";
        } else {
            $sizematch = "$size";
        }
        if (! isSupportedSize($keytype, $sizematch)) {
            &PKI::TPS::Wizard::debug_log("SizePanel: update size $size not supported");
            return 0;
        }
        $::config->put("preop.cert.".$certtag.".keysize.customsize", $size);
            $::config->put("preop.cert.".$certtag.".keytype", $keytype);

        if ($select eq "default") {
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
        return "nistp256";
    } elsif ($keytype eq "rsa") {
        return 2048;
    }

    $::symbol{errorString} = "Unsupported keytype $keytype";
    return 0;
}

sub isSupportedSize {
    my $keytype = $_[0];
    my $size = $_[1];

    if ($keytype eq "ecc") {
        my $keys_ecc_curve_list = $::config->get("keys.ecc.curve.list");
        if ($keys_ecc_curve_list eq "") {
            $keys_ecc_curve_list = "nistp256,nistp384,nistp521,sect163k1,nistk163,sect163r1,sect163r2,nistb163,sect193r1,sect193r2,sect233k1,nistk233,sect233r1,nistb233,sect239k1,sect283k1,nistk283,sect283r1,nistb283,sect409k1,nistk409,sect409r1,nistb409,sect571k1,nistk571,sect571r1,nistb571,secp160k1,secp160r1,secp160r2,secp192k1,secp192r1,nistp192,secp224k1,secp224r1,nistp224,secp256k1,secp256r1,secp384r1,secp521r1,prime192v1,prime192v2,prime192v3,prime239v1,prime239v2,prime239v3,c2pnb163v1,c2pnb163v2,c2pnb163v3,c2pnb176v1,c2tnb191v1,c2tnb191v2,c2tnb191v3,c2pnb208w1,c2tnb239v1,c2tnb239v2,c2tnb239v3,c2pnb272w1,c2pnb304w1,c2tnb359w1,c2pnb368w1,c2tnb431r1,secp112r1,secp112r2,secp128r1,secp128r2,sect113r1,sect113r2,sect131r1,sect131r2";
        }
        my @curves = split(/,/, $keys_ecc_curve_list);
        my $numcurves = @curves;
        foreach my $curve (@curves) {
           if ($size eq $curve) {
               #found curve
               return 1;
           } 
        }
        &PKI::TPS::Wizard::debug_log("SizePanel: isSupportedSize: curve $size unsupported");
        $::symbol{errorString} = "Unsupported curve $size. ECC only supports the the curves listed in Details";
        return 0;
    } else {
        #RSA 
        my $keys_rsa_size_list = $::config->get("keys.rsa.size.list");
        if ($keys_rsa_size_list eq "") {
            $keys_rsa_size_list = "1024,2048,3072,4096";
        }
        my @strengths = split(/,/, $keys_rsa_size_list);
        my $numstrengths = @strengths;
        foreach my $strength (@strengths) {
           if ($size eq $strength) {
               #found strength
               return 1;
           } 
        }

        # wrong size
        $::symbol{errorString} = "Unsupported Size $size. RSA only supports the sizes listed in Details";
        return 0;
    }
}

sub display
{
    my ($q) = @_;

    &PKI::TPS::Wizard::debug_log("SizePanel: display begins");

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
    if (($select eq "") || ($select eq "default")) {
        $::symbol{select} = "default";
    } else {
        &PKI::TPS::Wizard::debug_log("SizePanel: display keysize select= $select");
        $::symbol{select} = $select;
    }

    my $default_size = $::config->get("preop.keysize.size");
    if ($default_size eq "") {
        $::symbol{default_keysize} = 2048;
    } else {
        $::symbol{default_keysize} = $default_size;
    }

    #keys.ecc.curve.default=nistp256
    #keys.ecc.curve.display.list=nistp256 (secp256r1),nistp384 (secp384r1),nistp521 (secp521r1),nistk163 (sect163k1),sect163r1,nistb163 (sect163r2),sect193r1,sect193r2,nistk233 (sect233k1),nistb233 (sect233r1),sect239k1,nistk283 (sect283k1),nistb283 (sect283r1),nistk409 (sect409k1),nistb409 (sect409r1),nistk571 (sect571k1),nistb571 (sect571r1),secp160k1,secp160r1,secp160r2,secp192k1,nistp192 (secp192r1, prime192v1),secp224k1,nistp224 (secp224r1),secp256k1,prime192v2,prime192v3,prime239v1,prime239v2,prime239v3,c2pnb163v1,c2pnb163v2,c2pnb163v3,c2pnb176v1,c2tnb191v1,c2tnb191v2,c2tnb191v3,c2pnb208w1,c2tnb239v1,c2tnb239v2,c2tnb239v3,c2pnb272w1,c2pnb304w1,c2tnb359w1,c2pnb368w1,c2tnb431r1,secp112r1,secp112r2,secp128r1,secp128r2,sect113r1,sect113r2,sect131r1,sect131r2
    #keys.ecc.curve.list=nistp256,nistp384,nistp521,sect163k1,nistk163,sect163r1,sect163r2,nistb163,sect193r1,sect193r2,sect233k1,nistk233,sect233r1,nistb233,sect239k1,sect283k1,nistk283,sect283r1,nistb283,sect409k1,nistk409,sect409r1,nistb409,sect571k1,nistk571,sect571r1,nistb571,secp160k1,secp160r1,secp160r2,secp192k1,secp192r1,nistp192,secp224k1,secp224r1,nistp224,secp256k1,secp256r1,secp384r1,secp521r1,prime192v1,prime192v2,prime192v3,prime239v1,prime239v2,prime239v3,c2pnb163v1,c2pnb163v2,c2pnb163v3,c2pnb176v1,c2tnb191v1,c2tnb191v2,c2tnb191v3,c2pnb208w1,c2tnb239v1,c2tnb239v2,c2tnb239v3,c2pnb272w1,c2pnb304w1,c2tnb359w1,c2pnb368w1,c2tnb431r1,secp112r1,secp112r2,secp128r1,secp128r2,sect113r1,sect113r2,sect131r1,sect131r2
    my $keys_ecc_curve_list = $::config->get("keys.ecc.curve.list");
    if ($keys_ecc_curve_list eq "") {
        $::symbol{keys_ecc_curve_list} = "nistp256,nistp384,nistp521,sect163k1,nistk163,sect163r1,sect163r2,nistb163,sect193r1,sect193r2,sect233k1,nistk233,sect233r1,nistb233,sect239k1,sect283k1,nistk283,sect283r1,nistb283,sect409k1,nistk409,sect409r1,nistb409,sect571k1,nistk571,sect571r1,nistb571,secp160k1,secp160r1,secp160r2,secp192k1,secp192r1,nistp192,secp224k1,secp224r1,nistp224,secp256k1,secp256r1,secp384r1,secp521r1,prime192v1,prime192v2,prime192v3,prime239v1,prime239v2,prime239v3,c2pnb163v1,c2pnb163v2,c2pnb163v3,c2pnb176v1,c2tnb191v1,c2tnb191v2,c2tnb191v3,c2pnb208w1,c2tnb239v1,c2tnb239v2,c2tnb239v3,c2pnb272w1,c2pnb304w1,c2tnb359w1,c2pnb368w1,c2tnb431r1,secp112r1,secp112r2,secp128r1,secp128r2,sect113r1,sect113r2,sect131r1,sect131r2";
    } else {
        $::symbol{keys_ecc_curve_list} = $keys_ecc_curve_list;
    }

    my $keys_ecc_curve_display_list = $::config->get("keys.ecc.curve.display.list");
    if ($keys_ecc_curve_display_list eq "") {
        $::symbol{keys_ecc_curve_display_list} = "nistp256 (secp256r1),nistp384 (secp384r1),nistp521 (secp521r1),nistk163 (sect163k1),sect163r1,nistb163 (sect163r2),sect193r1,sect193r2,nistk233 (sect233k1),nistb233 (sect233r1),sect239k1,nistk283 (sect283k1),nistb283 (sect283r1),nistk409 (sect409k1),nistb409 (sect409r1),nistk571 (sect571k1),nistb571 (sect571r1),secp160k1,secp160r1,secp160r2,secp192k1,nistp192 (secp192r1, prime192v1),secp224k1,nistp224 (secp224r1),secp256k1,prime192v2,prime192v3,prime239v1,prime239v2,prime239v3,c2pnb163v1,c2pnb163v2,c2pnb163v3,c2pnb176v1,c2tnb191v1,c2tnb191v2,c2tnb191v3,c2pnb208w1,c2tnb239v1,c2tnb239v2,c2tnb239v3,c2pnb272w1,c2pnb304w1,c2tnb359w1,c2pnb368w1,c2tnb431r1,secp112r1,secp112r2,secp128r1,secp128r2,sect113r1,sect113r2,sect131r1,sect131r2"
    } else {
        $::symbol{keys_ecc_curve_display_list} = $keys_ecc_curve_display_list;
    }

    my $default_ecc_size =  $::config->get("preop.keysize.ecc.size");
    if (($default_ecc_size eq "") || ($default_ecc_size eq "256")) {
        $::symbol{default_ecc_curvename} = "nistp256";
    } else {
        $::symbol{default_ecc_curvename} = $default_ecc_size;
    }

    my $custom_size = $::config->get("preop.keysize.customsize");
#just leave custom size blank if not set
    if ($custom_size ne "") {
        $::symbol{custom_size} = $custom_size;
    } else {
        $::symbol{custom_size} = "enter size for RSA or curve name for ECC";
    }

    my $keys_rsa_size_display_list = $::config->get("keys.rsa.size.list");
    if ($keys_rsa_size_display_list eq "") {
        $::symbol{keys_rsa_size_display_list} = "1024,2048,3072,4096";
    } else {
        $::symbol{keys_rsa_size_display_list} = $keys_rsa_size_display_list;
    }

    &PKI::TPS::Wizard::debug_log("SizePanel: display ends");

    return 1;
}

sub is_panel_done
{
   return $::config->get("preop.SizePanel.done");
}

1;
