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
use XML::Simple;
use Data::Dumper;

package PKI::TPS::SecurityDomainPanel;
$PKI::TPS::SecurityDomainPanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&is_panel_done;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(1);
    $self->{"getName"} = &PKI::TPS::Common::r("Security Domain");
    $self->{"vmfile"} = "securitydomainpanel.vm";
    $self->{"update"} = \&update;
    $self->{"panelvars"} = \&display;
    bless $self,$class; 
    return $self; 
}

sub validate
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("SecurityPanel: validate");

    return 1;
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

sub pingCS
{
    my( $instanceDir ) = $_[0];
    my( $db_password ) = $_[1];
    my( $nickname ) = $_[2];
    my( $hostname ) = $_[3];
    my( $port ) = $_[4];

    my $content = `/usr/bin/sslget -d $instanceDir/alias -p $db_password -v -r "/ca/admin/ca/getStatus" $hostname:$port`;
    if( "$content" eq "" ) {
        return 0;
    } else {
        $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
        $content = $1;

        my $parser = XML::Simple->new();
        my $response = $parser->XMLin($content);
        my $state = $response->{State};

        if( "$state" eq "1" ) {
            return 1;
        } else {
            return 0;
        }
    }
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("SecurityPanel: display");
    $::symbol{panelname} = "Security Domain";
    $::symbol{sdomainName} = "Security Domain";

    my $instanceDir = $::config->get("service.instanceDir");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;
    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    my $hostname = $::config->get("service.machineName");
    my $default_https_admin_port = 9445;

    # check to see if "default" security domain exists on local machine
    my $status = pingCS( $instanceDir,
                         $db_password,
                         $nickname,
                         $hostname,
                         $default_https_admin_port );
    if( "$status" eq "1" ) {
        # "default" security domain exists on local machine;
        # fill "sdomainURL" in with "default" security domain
        # as an initial "guess"
        $::symbol{sdomainURL} = "https://" . $hostname . ":"
                              . $default_https_admin_port;
    } else {
        # "default" security domain does NOT exist on local machine;
        # leave "sdomainURL" blank
        $::symbol{sdomainURL} = "";
    }

    $::symbol{sdomainAdminURL} = "https://" . $hostname . ":"
                               . $default_https_admin_port;

    my $initDaemon = "pki-tomcatd";
    my $statusCommand = "";
    my $instanceID = "&lt;security_domain_instance_name&gt;";
    if( $^O eq "linux" ) {
        $statusCommand = "systemctl status $initDaemon\@$instanceID.service";
    } else {
        ## default case:  e. g. - ( $^O eq "solaris" )
        $statusCommand  = "/etc/init.d/$initDaemon status $instanceID";
    }
    $::symbol{statusCommand} = $statusCommand;
    $::symbol{instanceID}  = $instanceID;
    return 1;
}


sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("SecurityPanel: update");
    my $sdomainURL = $q->param("sdomainURL");

    if ($sdomainURL eq "") {
        &PKI::TPS::Wizard::debug_log("SecurityPanel: sdomainURL has not been specified!");
        $::symbol{errorString} = "Security Domain HTTPS has not been specified!";
        return 0;
    }

    my $sdomainURL_info = new URI::URL($sdomainURL);

    my $instanceDir = $::config->get("service.instanceDir");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;
    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    my $hostname = $sdomainURL_info->host;
    my $https_admin_port = $sdomainURL_info->port;

    # check to see if "default" security domain exists on local machine
    my $status = pingCS( $instanceDir,
                         $db_password,
                         $nickname,
                         $hostname,
                         $https_admin_port );
    if( "$status" ne "1" ) {
        # invalid security domain specified
        &PKI::TPS::Wizard::debug_log("SecurityPanel: sdomainURL not found");
        $::symbol{errorString} = "Security Domain HTTPS Admin URL not found";
        return 0;
    }

    # save urls in CS.cfg
    &PKI::TPS::Wizard::debug_log("SecurityPanel: sdomainURL=" . $sdomainURL);
    $::config->put("config.sdomainAdminURL", $sdomainURL);

    # Add values necessary for 'pkiremove' . . .
    $::config->put("securitydomain.select", "existing");
    $::config->put("securitydomain.host", $sdomainURL_info->host);
    $::config->put("securitydomain.httpsadminport", $sdomainURL_info->port);
    $::config->put("preop.securitydomain.done", "true");
    $::config->commit();

    return 1;
}

sub is_panel_done
{
   return $::config->get("preop.securitydomain.done");
}

1;
