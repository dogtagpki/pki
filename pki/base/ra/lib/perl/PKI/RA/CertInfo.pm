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

package PKI::RA::CertInfo;
$PKI::RA::CertInfo::VERSION = '1.00';

sub new {
    my ($class, $name, $dn, $tag) = @_;
    my $self = {};

    &PKI::RA::Wizard::debug_log("CertInfo: start new");
    $self->{"getUserFriendlyName"} = \&get_user_friendly_name;
    $self->{"getCertTag"} = \&get_cert_tag;
    $self->{"getDN"} = \&get_dn;
    $self->{"getNickname"} = \&get_nickname;
    $self->{"useDefaultKey"} = \&use_default_key;
    $self->{"getCustomKeysize"} = \&get_custom_keysize;
    $self->{"keyOption"} = \&get_key_option;
    &PKI::RA::Wizard::debug_log("CertInfo: end new");

    $self->{name} = $name;
    $self->{dn} = $dn;
    $self->{tag} = $tag;

    bless $self, $class;
    return $self;
}

sub get_user_friendly_name
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("CertInfo: get_user_friendly_name");
    return $self->{name};
}

sub get_cert_tag
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("CertInfo: get_cert_tag");
    return $self->{tag};
}

sub get_dn
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("CertInfo: get_cert_dn");
    return $self->{dn};
}

sub use_default_key
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("CertInfo: use_default_key");
    my $option = $::config->get("preop.cert.$self->{tag}.keysize.select");
    if (($option ne "") && ($option ne "default")) {
        return 0;
    }
    return 1;
}

sub get_nickname
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("CertInfo: get_nickname");
    my $nickname = $::config->get("preop.cert.$self->{tag}.nickname");

    my $flavor = "pki";
    $flavor =~ s/\n//g;

    if ($nickname ne "") {
        return $nickname;
    } else {
        return  $self->{tag}."cert cert-$flavor-ra";
    }
}

sub get_key_option
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("CertInfo: get_key_option");
    my $option = $::config->get("preop.cert.$self->{tag}.keysize.select");

    if ($option ne "") {
        &PKI::RA::Wizard::debug_log("CertInfo: get_key_option from config = $option");
        return $option;
    } else {
        &PKI::RA::Wizard::debug_log("CertInfo: get_key_option not from config");
        return "default";
    }
}

sub get_custom_keysize
{
    my ($self) = @_;
    &PKI::RA::Wizard::debug_log("CertInfo: get_custom_keysize");
    my $size = $::config->get("preop.cert.$self->{tag}.keysize.customsize");
    &PKI::RA::Wizard::debug_log("CertInfo: get_custom_keysize for preop.cert.$self->{tag}.keysize.customsize is $size");
    if ($size ne "") {
        &PKI::RA::Wizard::debug_log("CertInfo: get_custom_keysize from config is $size");
        return $size;
    } else {
        &PKI::RA::Wizard::debug_log("CertInfo: get_custom_keysize not from config");
        return 2048;
    }
}

1;
