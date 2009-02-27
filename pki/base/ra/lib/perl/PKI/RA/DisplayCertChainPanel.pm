#!/usr/bin/pkiperl
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
use URI::URL;
use MIME::Base64;

package PKI::RA::DisplayCertChainPanel;
$PKI::RA::DisplayCertChainPanel::VERSION = '1.00';

use PKI::RA::BasePanel;
our @ISA = qw(PKI::RA::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::RA::Common::no;
    $self->{"getPanelNo"} = &PKI::RA::Common::r(2);
    $self->{"getName"} = &PKI::RA::Common::r("Display Certificate Chain");
    $self->{"vmfile"} = "displaycertchainpanel.vm";
    $self->{"update"} = \&update;
    $self->{"panelvars"} = \&display;
    bless $self,$class; 
    return $self; 
}

sub is_sub_panel
{
    my ($q) = @_;
    return 1;
}

sub has_sub_panel
{
    my ($q) = @_;
    return 0;
}

sub validate
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: validate");
    return 1;
}

sub readFile
{
    my $fn = $_[0];
    open FILE, "< $fn" or return "";
    my $content =  join "",<FILE>;
    close FILE;

    return $content;
}

sub update
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: update");

    my $instanceDir = $::config->get("service.instanceDir");

    my $caCert = readFile("$instanceDir/conf/caCert.txt");

    #store in config
    $::config->put("preop.ca.certchain", $caCert);
    $::config->commit();

    # import it into the security database
#    my $cmd1 = `/usr/bin/AtoB $instanceDir/conf/caCert.txt $instanceDir/conf/caCert.der`;
    my $cmd2 = `/usr/bin/certutil -A -d \"$instanceDir/alias\" -t \"CT,CT,CT\" -n \"caCert\" -i $instanceDir/conf/caCert.der`;

    # clean up
    my $tmp = `rm $instanceDir/conf/caCert.txt`;
    $tmp = `rm $instanceDir/conf/caCert.der`;
    $tmp = `rm $instanceDir/conf/caCert_pp.txt`;

    # complete the SeucrityDomain task
    my $sdomainURL =  $::config->get("config.sdomainURL");
    if ($sdomainURL eq "") {
        return 2;
      }

    my $machineName = $::config->get("service.machineName");
    my $securePort = $::config->get("service.securePort");
    my $unsecurePort = $::config->get("service.unsecurePort");

    # check if url is accessible
    # redirect to the security domain authentication
    if ($ENV{'SERVER_PORT'} eq $unsecurePort) {
       $::symbol{redirect} = $sdomainURL . "/ca/ee/ca/securityDomainLogin?url=http%3A%2F%2F" . $machineName . "%3A" . $unsecurePort . "%2Fra%2Fadmin%2Fconsole%2Fconfig%2Fwizard%3Fp%3D3%26subsystem%3DRA";
    } else {
       $::symbol{redirect} = $sdomainURL . "/ca/ee/ca/securityDomainLogin?url=https%3A%2F%2F" . $machineName . "%3A" . $securePort . "%2Fra%2Fadmin%2Fconsole%2Fconfig%2Fwizard%3Fp%3D3%26subsystem%3DRA";
    }

    get_domain_xml($sdomainURL);


    return 3;
}

sub display
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: display");

    # connect to the CA, and retrieve the CA certificate
    &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: update connecting to CA and retrieve cert chain");
    my $instanceID = $::config->get("service.instanceID");
    my $instanceDir = $::config->get("service.instanceDir");
    my $sdomainURL =  $::config->get("config.sdomainURL");
    if ($sdomainURL eq "") {
        return 2;
      }

    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

    my $url_info = new URI::URL($sdomainURL);
    my $host = $url_info->host;
    my $port = $url_info->port;
    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    my $cmd = `/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$nickname\" -r \"/ca/ee/ca/getCertChain\" $host:$port`;

    my $caCert;
    if ($cmd =~ /\<ChainBase64\>(.*)\<\/ChainBase64\>/) {
        $caCert =  $1;
        &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: ca= $caCert");
    }

    my $certpp;
    if ($caCert ne "") {
        open(F, ">$instanceDir/conf/caCert.txt");
        print F $caCert;
        close(F);

        # test to see if tmp directory exists, if not, create
        my $found =  -e "$instanceDir/conf/tmp";
        if (! $found) {
            my $tmp = `mkdir $instanceDir/conf/tmp`;
        }

        # import it into a temporary security database
#        my $cmd1 = `/usr/bin/AtoB $instanceDir/conf/caCert.txt $instanceDir/conf/caCert.der`;
        # my $cmd1 = `/usr/bin/openssl base64 -d -A -in $instanceDir/conf/caCert.txt -out $instanceDir/conf/caCert.der`;

        my $txt = `cat $instanceDir/conf/caCert.txt`;
        open(OUT, ">$instanceDir/conf/caCert.der");
        print OUT MIME::Base64::decode($txt);
        close(OUT);

        my $cmd2 = `/usr/bin/certutil -A -d \"$instanceDir/conf/tmp\" -t \"CT,CT,CT\" -n \"caCert\" -i $instanceDir/conf/caCert.der`;

        # get pretty print from temp db
        my $tmp = `certutil -d $instanceDir/conf/tmp -n "caCert" -L > $instanceDir/conf/caCert_pp.txt`;
        $certpp = readFile("$instanceDir/conf/caCert_pp.txt");
        $certpp =~ s/"//g;
        &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: certpp= $certpp");
        # clean up temp db
        $tmp = `certutil -d $instanceDir/alias/tmp -D -n "caCert"`;
    } else {
        &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: update no certchain found");
    }

    &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: display certchain=$caCert");

#               $symbol{certchain}        = [ "cert1", "cert2" ];
#               $symbol{certchain_size}   = 2;
    $::symbol{certchain}        = "$certpp";
# This certchain_size does not matter
    $::symbol{certchain_size}   = 1;

    return 1;
}
sub get_domain_xml
{
    my ($sdomainURL) = @_;

    my $sdom_info = new URI::URL($sdomainURL);
    # get the domain xml
    # e. g. - https://water.sfbay.redhat.com:9444/ca/ee/ca/getDomainXML

    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    my $instanceID = $::config->get("service.instanceID");
    my $instanceDir = $::config->get("service.instanceDir");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

    my $host = $sdom_info->host;
    my $port = $sdom_info->port;
    my $content = `/usr/bin/sslget -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$nickname\" -r \"/ca/ee/ca/getDomainXML\" $host:$port`;

    $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $content = $1;

    &PKI::RA::Wizard::debug_log("content = " . $content);

    my $parser = XML::Simple->new();
    my $response = $parser->XMLin($content);
    my $xml = $parser->XMLin($response->{'DomainInfo'},
                       ForceArray => 1);
   
    &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: security domain '" . 
                $xml->{'Name'}[0] . "'");
    $::config->put("preop.securitydomain.name", $xml->{'Name'}[0]);

    # parse xml and store information in CS.cfg
    my $count = 0;
    $count = 0;
    foreach my $c (@{$xml->{'CAList'}[0]->{'CA'}}) {
        &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: Found CA '" . 
              $c->{'SubsystemName'}[0] . "'");
        $::config->put("preop.securitydomain.ca" . $count . ".subsystemname", 
                        $c->{'SubsystemName'}[0]);
        $::config->put("preop.securitydomain.ca" . $count . ".secureport", 
                        $c->{'SecurePort'}[0]);
        $::config->put("preop.securitydomain.ca" . $count . ".host", 
                        $c->{'Host'}[0]);
        $count++;
    }

    $count = 0;
    foreach my $c (@{$xml->{'TKSList'}[0]->{'TKS'}}) {
        &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: Found TKS '" . 
              $c->{'SubsystemName'}[0] . "'");
        $::config->put("preop.securitydomain.tks" . $count . ".subsystemname", 
                        $c->{'SubsystemName'}[0]);
        $::config->put("preop.securitydomain.tks" . $count . ".secureport", 
                        $c->{'SecurePort'}[0]);
        $::config->put("preop.securitydomain.tks" . $count . ".host", 
                        $c->{'Host'}[0]);
        $count++;
    }

    $count = 0;
    foreach my $c (@{$xml->{'KRAList'}[0]->{'KRA'}}) {
       &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: Found KRA '" . 
              $c->{'SubsystemName'}[0] . "'");
        $::config->put("preop.securitydomain.kra" . $count . ".subsystemname", 
                        $c->{'SubsystemName'}[0]);
        $::config->put("preop.securitydomain.kra" . $count . ".secureport", 
                        $c->{'SecurePort'}[0]);
        $::config->put("preop.securitydomain.kra" . $count . ".host", 
                        $c->{'Host'}[0]);
        $count++;
    }

    $count = 0;
    foreach my $c (@{$xml->{'RAList'}[0]->{'RA'}}) {
       &PKI::RA::Wizard::debug_log("DisplayCertChainPanel: Found RA '" . 
              $c->{'SubsystemName'}[0] . "'");
        $::config->put("preop.securitydomain.ra" . $count . ".subsystemname", 
                        $c->{'SubsystemName'}[0]);
        $::config->put("preop.securitydomain.ra" . $count . ".secureport", 
                        $c->{'SecurePort'}[0]);
        $::config->put("preop.securitydomain.ra" . $count . ".host", 
                        $c->{'Host'}[0]);
        $count++;
    }
    $::config->commit();
}

1;
