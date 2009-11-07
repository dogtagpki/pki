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
use PKI::TPS::Modutil;

package PKI::TPS::ModulePanel;
$PKI::TPS::ModulePanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

our $modutil;

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&is_panel_done;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(9);
    $self->{"getName"} = &PKI::TPS::Common::r("Security Modules");
    $self->{"vmfile"} = "modulepanel.vm";
    $self->{"update"} = \&update;
    $self->{"panelvars"} = \&display;

    my $flavor = "pki";
    $flavor =~ s/\n//g;

    my $pkiroot = $ENV{PKI_ROOT};
	$modutil = new PKI::TPS::Modutil("$pkiroot/alias");

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
    return 1;
}

sub validate
{
    my ($q) = @_;
    return 1;
}

sub update
{
    my ($q) = @_;
    my $defTok = $::config->get("preop.module.token");
    my $select = $q->param('choice');
    if ($select eq "") {
        &PKI::TPS::Wizard::debug_log("ModulePanel -> update no selection found");
        $::symbol{errorString} = "No selection found";
        return 0;
    } elsif ($defTok ne $select) {
        &PKI::TPS::Wizard::debug_log("ModulePanel -> update changing defTok to $select");
        $::config->put("preop.module.token", $select);
    } else {
        # this is not an error...just information
        &PKI::TPS::Wizard::debug_log("ModulePanel -> update  defTok not changed");
    }

    $::config->put("preop.ModulePanel.done", "true");

    $::config->commit();
    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("ModulePanel -> display");
    getModules();
    my $defTok = $::config->get("preop.module.token");

    $::symbol{defTok}   = $defTok;

     return 1;
}

use Data::Dumper;
sub getTokens {
 my $modulename = shift;
 
 &PKI::TPS::Wizard::debug_log("ModulePanel -> getTokens");

#$Data::Dumper::Indent = 0;
#PKI::TPS::Wizard::dbg("in gettokens. modutil = ".Dumper($modutil));
 my @tokens;
 my $mod = $modutil->getmodule($modulename);
 foreach my $tokenname (keys %{$mod->{tokens}}) {
    #PKI::TPS::Wizard::dbg("found token $tokenname");
    if ($tokenname ne "NSS Generic Crypto Services") {
        my $token = $modutil->gettoken($tokenname);
        my $t = new PKI::TPS::GlobalVar(
                        getNickName        => sub { return $tokenname; },
                        isLoggedIn         => sub { return isLoggedIn($tokenname); },
                        isPresent          => sub { return 1; },
                        );
        push @tokens, $t;
    } else {
        &PKI::TPS::Wizard::debug_log("ModulePanel -> getTokens token NSS Generic Crypto Services not available for key generation");

    }
 }

 return \@tokens;
}

# if password is found, then it's considered "logged in"
# otherwise it is "not logged in"
sub Login {
    my $tokenname = $_[0];
    my $pwd = $::pwdconf->get($tokenname);
    if ($pwd ne "") {
        &PKI::TPS::Wizard::debug_log("ModulePanel -> isLoggedIn retrieved pwd from pwdconf");
        return 1;
    }
    &PKI::TPS::Wizard::debug_log("ModulePanel -> isLoggedIn pwd not found from pwdconf for token: $tokenname");

    if ($tokenname eq "NSS Certificate DB") {
        my $instanceDir = $::config->get("service.instanceDir");
        &PKI::TPS::Wizard::debug_log("ModulePanel -> isLoggedIn get internal password for $tokenname");
        # these are referred as "internal" in password.conf
        $pwd = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
        $pwd =~ s/\n//g;
        $::pwdconf->put($tokenname, $pwd);
        $::pwdconf->commit();

        return 1;
    }
    return 0;
}

sub isLoggedIn {
    my $tokenname = $_[0];
    return &Login($tokenname);
}

sub getModules {
    my $count;
    my $i;
    my @supportedModules;
 
    &PKI::TPS::Wizard::debug_log("ModulePanel -> getModules");
    $count = $::config->get("preop.configModules.count");
    &PKI::TPS::Wizard::debug_log("ModulePanel -> getModules count =$count");

    my @modules = $modutil->getmodules();
  #  $::symbol{steve} = join ",Module:", @modules;
  #  $::symbol{steve}.= "\n";

    my $x = "
        preop.configModules.count=3
        preop.configModules.module0.commonName=NSS Internal PKCS #11 Module
        preop.configModules.module0.imagePath=../img/mozilla.png
        preop.configModules.module0.userFriendlyName=NSS Internal PKCS #11 Module
        preop.configModules.module1.commonName=nfast
        preop.configModules.module1.imagePath=../img/ncipher.png
        preop.configModules.module1.userFriendlyName=nCipher's nFast Token Hardware Module
        preop.configModules.module2.commonName=lunasa
        preop.configModules.module2.imagePath=../img/safenet.png
        preop.configModules.module2.userFriendlyName=SafeNet's LunaSA Token Hardware Module
        ";

    my %supmodules;
    for ($i=0; $i <$count; $i++) {
        my $cn;
        my $pn;
        my $img;
#   &PKI::TPS::Wizard::debug_log("ModulePanel -> getModules look for cn=","preop.configModules.module" , $i , ".commonName");
        $cn = $::config->get("preop.configModules.module$i.commonName");
        $supmodules{$cn} = 1;

        $pn = $::config->get("preop.configModules.module$i.userFriendlyName");
        $img = $::config->get("preop.configModules.module$i.imagePath");
        &PKI::TPS::Wizard::debug_log("ModulePanel -> getModules: got module $cn from config");

        my $module = $modutil->getmodule($cn);
        my $file   = $module->{detail}->{"Library file"};
         &PKI::TPS::Wizard::debug_log("ModulePanel -> getModules Library file = $file");
        my $found = 0;
        if ($file) {
            $found  =  ($file =~ /Internal ONLY module/)  || -e $file;
        }

        my $name = $module->{detail}->{Name};
#   PKI::TPS::Wizard::dbg("name: $name");

        $supportedModules[$i] = new  PKI::TPS::GlobalVar(
                        getImagePath        => sub { return $img; },
                        getUserFriendlyName => sub { return $pn; },
                        isFound             => sub { return $found; },
                        getTokens           => sub { return getTokens($name); },
                        );

        # login to tokens
        &PKI::TPS::Wizard::debug_log("Ready to login to tokens for $name");
        my $mod = $modutil->getmodule($name);
        foreach my $tokenname (keys %{$mod->{tokens}}) {
          &PKI::TPS::Wizard::debug_log("Logging in Module $name Token " . $tokenname);
          &Login($tokenname);
        }

    }

    my @otherModules;
    #compile the "others" modules

    foreach my $modname (@modules) {
    #is this modname in the supported modules list?
        if ($supmodules{$modname}) {
            &PKI::TPS::Wizard::debug_log("ModulePanel -> getModules: found module $modname supported");
	    # does not belong to "others"
        } else {
            &PKI::TPS::Wizard::debug_log("ModulePanel -> getModules: found module $modname unsupported");
            #add the module to "others" list
	    my $m = $modutil->getmodule($modname);
            my $mod = new  PKI::TPS::GlobalVar(
                        getImagePath        => sub { return ""; },
                        getUserFriendlyName => sub { return $m->{modulename}; },
                        isFound             => sub { return 1; },
                        getTokens           => sub { return getTokens($m->{detail}->{Name});}
            );

            push @otherModules, $mod;

            &PKI::TPS::Wizard::debug_log("ModulePanel -> getModules: module $modname added to otherModules list");
        }
    }

    $::symbol{sms}   = \@supportedModules;
    $::symbol{oms}   = \@otherModules;
#  PKI::TPS::Wizard::dbg("oms: ". Dumper([@otherModules]));
#  PKI::TPS::Wizard::dbg("sms: ". Dumper([@supportedModules]));

    &PKI::TPS::Wizard::debug_log("ModulePanel -> set sms, oms");
}

sub is_panel_done
{
   return $::config->get("preop.ModulePanel.done");
}

1;
