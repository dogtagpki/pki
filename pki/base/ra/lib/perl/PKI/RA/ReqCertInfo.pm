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

package PKI::RA::ReqCertInfo;
$PKI::RA::ReqCertInfo::VERSION = '1.00';

our $cert_req_header="-----BEGIN NEW CERTIFICATE REQUEST-----";
our $cert_req_footer="-----END NEW CERTIFICATE REQUEST-----";
our $cert_header="-----BEGIN CERTIFICATE-----";
our $cert_footer="-----END CERTIFICATE-----";

sub new {
    my ($class, $name, $dn, $tag) = @_;
    my $self = {};
    &PKI::RA::Wizard::debug_log("ReqCertInfo: start new");
    &PKI::RA::Wizard::debug_log("ReqCertInfo: creating name: $name, dn: $dn, tag: $tag");

    $self->{"getUserFriendlyName"} = \&get_user_friendly_name;
    $self->{"getCertTag"} = \&get_cert_tag;
    $self->{"getCert"} = \&get_cert;
    $self->{"getCertpp"} = \&get_cert_pp;
    $self->{"getRequest"} = \&get_request;
    $self->{"getDN"} = \&get_dn;
    $self->{"useDefaultKey"} = \&use_default_key;
    $self->{"getCustomKeysize"} = \&get_custom_keysize;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: end new");

    $self->{name} = $name;
    $self->{dn} = $dn;
    $self->{tag} = $tag;

    bless $self, $class;
    return $self;
}

sub get_user_friendly_name
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: get_user_friendly_name");
    return $self->{name};
}

sub readFile
{
    my $fn = $_[0];
    open FILE, "< $fn" or return "";
    my $content =  join "",<FILE>;
    close FILE;

    return $content;
}

sub wrap_lines
{
   my $lines = shift;
    my $temp ;
    foreach my $line (split "\n", $lines) {
	if (length $line > 59) {
    		$line =~ s/(.{0,60})/$1\n/g;
	}
	# get rid of a line that is just an empty newline
	$line =~ s/^\n$//gms;
	$temp .= $line;
    }
    # collapse multiple newlines into one
    $temp =~ s/\n+/\n/gms;
    $temp =~ s/\n$//gms;
    $temp;

}

sub get_request
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: get_request");
    # first, try to see if request has been made before
#    my $req = readFile( "/var/lib/pki-ra/conf/$self->{tag}_cert_request.txt");

    my $req = $::config->get("preop.cert.$self->{tag}.certreq");
    
    $req = wrap_lines($req);
    
    if ($req ne "") {
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_request found existing request");
        return $cert_req_header."\n".$req."\n".$cert_req_footer;;
    } else {
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_request existing request not found");
    }

    return $req;
}

sub get_cert
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert");
#   see if there is an existing cert
#    my $cert =  readFile("/var/lib/pki-ra/conf/".$self->{tag}."_cert.txt");
    my $cert = $::config->get("preop.cert.$self->{tag}.cert");

    $cert = wrap_lines($cert);
    if ($cert ne "") {
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert found existing cert");
        return $cert_header."\n".$cert."\n".$cert_footer;;
    } else {
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert existing cert not found");
    }
    if ($cert eq "") {
        $cert = "...paste certificate here...";
    }


    return $cert;
}

sub get_cert_pp
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert_pp");
    my $instanceDir =  $::config->get("service.instanceDir");

    my $hw;
    my $tokenname = $::config->get("preop.module.token");
    &PKI::RA::Wizard::debug_log("ReqCertInfo: update got token name = $tokenname");

    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        $hw = "";
    } else {
        $hw = "-h $tokenname";
    }

    my $token_pwd = $::pwdconf->get($tokenname);
    open FILE, ">$instanceDir/conf/.pwfile";
    system( "chmod 00660 $instanceDir/conf/.pwfile" );
    $token_pwd  =~ s/\n//g;
    print FILE $token_pwd;
    close FILE;

    my $nickname = $::config->get("preop.cert.$self->{tag}.nickname");
    if ($nickname eq "") {
#XXX
        $nickname = "RA ".$self->{tag}." cert";
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert_pp nickname not found for $self->{tag}  -- try $nickname");
    }
    my $certpp="";
#    my $found = -e "/var/lib/pki-ra/conf/$self->{tag}_cert.txt";
    my $cert = $::config->get("preop.cert.$self->{tag}.cert");

    if ($cert ne "") {
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert_pp found request, ready to get prettyprint");
        my $tmp = `certutil -d $instanceDir/alias $hw -f $instanceDir/conf/.pwfile -n "$nickname" -L > $instanceDir/conf/$self->{tag}_cert_pp.txt`;
        $certpp = readFile("$instanceDir/conf/$self->{tag}_cert_pp.txt");
        $certpp =~ s/"//g;
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert_pp pp=$certpp");
        $tmp =`rm $instanceDir/conf/$self->{tag}_cert_pp.txt`;
    } else {
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert_pp cert not found, will not get prettyprint");
    }
    my $tmp = `rm $instanceDir/conf/.pwfile`;

    return $certpp;
}

sub get_cert_tag
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert_tag");
    return $self->{tag};
}

sub get_dn
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: get_cert_dn");
    return $self->{dn};
}

sub use_default_key
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: use_default_key");
    my $select = $::config->get("preop.cert.$self->{tag}.keysize.select");
    if ($select ne "") {
        if ($select eq "custom") {
            &PKI::RA::Wizard::debug_log("ReqCertInfo: use_default_key from config = $select returning 0");
            return 0;
        }
    }

    &PKI::RA::Wizard::debug_log("ReqCertInfo: use_default_key returning 1");
    return 1;
}

sub get_custom_keysize
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("ReqCertInfo: get_custom_keysize");
    my $keysize = $::config->get("preop.cert.$self->{tag}.keysize.customsize");
    if ($keysize ne "") {
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_custom_keysize from config = $keysize");
        return $keysize;
    } else {
        &PKI::RA::Wizard::debug_log("ReqCertInfo: get_custom_keysize not from config");
    }
    return 2048;
}


1;
