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
use URI::URL;
use XML::Simple;

package PKI::RA::DonePanel;
$PKI::RA::DonePanel::VERSION = '1.00';

use PKI::RA::BasePanel;
our @ISA = qw(PKI::RA::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::RA::Common::no;
    $self->{"getPanelNo"} = &PKI::RA::Common::r(16);
    $self->{"getName"} = &PKI::RA::Common::r("Done");
    $self->{"vmfile"} = "donepanel.vm";
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
    &PKI::RA::Wizard::debug_log("DonePanel: validate");
    return 1;
}
sub update
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DonePanel: update");
    return 1;
}

sub register_ra
{
    my ($sdom, $url, $uri, $xname) = @_;

    &PKI::RA::Wizard::debug_log("DonePanel: register_ra at $url");
    &PKI::RA::Wizard::debug_log("DonePanel: subsystem $xname uri=$uri");

    my $url_info = new URI::URL($url);
    my $sdom_info = new URI::URL($sdom);

    # register RA to Security Domain
    # submit request to CA
    &PKI::RA::Wizard::debug_log("DonePanel: Connecting to Security Domain");

    my $machineName = $::config->get("service.machineName");
    my $unsecurePort = $::config->get("service.unsecurePort");
    my $securePort = $::config->get("service.securePort");
    my $non_clientauth_securePort = $::config->get("service.non_clientauth_securePort");
    my $session_id = $::config->get("preop.sessionID");

    &PKI::RA::Wizard::debug_log("DonePanel: Security Domain Info " . $url);

    # add service.securityDomainPort to the config file in case pkiremove
    # needs to remove system reference from the security domain
    $::config->put("service.securityDomainPort", $securePort);
    $::config->commit();

    my $uid = "RA-" . $machineName . "-" . $securePort;
    my $name = "Registration Authority Subsystem";

    my $instDir = $::config->get("service.instanceDir");
    my $nickname = $::config->get("preop.cert.sslserver.nickname");

    my $hw;
    my $tk;
    my $tokenname = $::config->get("preop.module.token");
    &PKI::RA::Wizard::debug_log("ReqCertInfo: update got token name = $tokenname");

    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        $hw = "";
        $tk = "";
    } else {
        $hw = "-h $tokenname";
        $tk = $tokenname.":";
    }

    my $token_pwd = $::pwdconf->get($tokenname);
    open FILE, ">$instDir/conf/.pwfile";
    system( "chmod 00660 $instDir/conf/.pwfile" );
    $token_pwd  =~ s/\n//g;
    print FILE $token_pwd;
    close FILE;

    my $subsystemNickname = $::config->get("preop.cert.subsystem.nickname");
    my $certificate = `/usr/bin/certutil -d "$instDir/alias" -L $hw -f "$instDir/conf/.pwfile" -n "$subsystemNickname" -a`;
    $certificate =~ s/-----BEGIN CERTIFICATE-----//g;
    $certificate =~ s/-----END CERTIFICATE-----//g;
    $certificate =~ s/\n$//g;


    &PKI::RA::Wizard::debug_log("DonePanel: Connecting");

    my $instanceID = $::config->get("service.instanceID");
    my $instanceDir = $::config->get("service.instanceDir");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

    my $params = "uid=" . $uid . "&" .
                  "name=" . $name . "&" .
                  "certificate=" .
                      URI::Escape::uri_escape("$certificate") . "&" .
                  "xmlOutput=true" . "&" .
                  "sessionID=" . $session_id .  "&" .
                  "auth_hostname=" . $sdom_info->host . "&" .
                  "auth_port=" . $sdom_info->port;

    my $host = $url_info->host;
    my $port = $url_info->port;
    my $tmpfile = "/tmp/donepanel-$$";
    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        system("/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$nickname\" -r \"$uri\" $host:$port > $tmpfile");
    } else {
        system("/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$token_pwd\" -v -n \"$nickname\" -r \"$uri\" $host:$port > $tmpfile");
    }
    my $content = `cat $tmpfile`;
    system("rm $tmpfile");

    &PKI::RA::Wizard::debug_log("req = " . $content);
    $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $content = $1;

    &PKI::RA::Wizard::debug_log("DonePanel: result " . $content);
    my $tmp = `rm $instDir/conf/.pwfile`;
}

sub get_kra_transport_cert
{
    my ($sdom) = @_;

    my $sdom_info = new URI::URL($sdom);

    # register RA to Security Domain
    # submit request to CA
    &PKI::RA::Wizard::debug_log("DonePanel: Connecting to KRA");

    my $krainfo = $::config->get("preop.krainfo.select");
    my $krainfo_url = new URI::URL($krainfo);

    my $machineName = $::config->get("service.machineName");
    my $unsecurePort = $::config->get("service.unsecurePort");
    my $securePort = $::config->get("service.securePort");
    my $non_clientauth_securePort = $::config->get("service.non_clientauth_securePort");
    my $session_id = $::config->get("preop.sessionID");

    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    my $tokenname = $::config->get("preop.module.token");
    my $token_pwd = $::pwdconf->get($tokenname);
    my $instanceID = $::config->get("service.instanceID");
    my $instanceDir = $::config->get("service.instanceDir");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

    my $params = "sessionID=" . $session_id .  "&" .
                  "auth_hostname=" . $sdom_info->host . "&" .
                  "auth_port=" . $sdom_info->port;

    my $host = $krainfo_url->host;
    my $port = $krainfo_url->port;
    my $tmpfile = "/tmp/donepanel-$$";
    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        system("/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$db_password\" -v -r \"/kra/admin/kra/getTransportCert\" $host:$port > $tmpfile");
    } else {
        system("/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$token_pwd\" -v -r \"/kra/admin/kra/getTransportCert\" $host:$port > $tmpfile");
    }
    my $content = `cat $tmpfile`;
    system("rm $tmpfile");

    $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $content = $1;

    my $parser = XML::Simple->new();
    my $response = $parser->XMLin($content);
    my $transportCert = $response->{TransportCert};
    
    &PKI::RA::Wizard::debug_log("DonePanel: TransportCert " . $transportCert);

    return $transportCert;
}

sub send_kra_transport_cert
{
    my ($sdom, $certificate) = @_;

    my $sdom_info = new URI::URL($sdom);

    # register RA to Security Domain
    # submit request to CA
    &PKI::RA::Wizard::debug_log("DonePanel: Connecting to TKS");
    my $tksinfo = $::config->get("preop.tksinfo.select");
    my $tksinfo_url = new URI::URL($tksinfo);

    my $machineName = $::config->get("service.machineName");
    my $unsecurePort = $::config->get("service.unsecurePort");
    my $securePort = $::config->get("service.securePort");
    my $non_clientauth_securePort = $::config->get("service.non_clientauth_securePort");
    my $session_id = $::config->get("preop.sessionID");

    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    my $tokenname = $::config->get("preop.module.token");
    my $token_pwd = $::pwdconf->get($tokenname);
    my $instanceID = $::config->get("service.instanceID");
    my $instanceDir = $::config->get("service.instanceDir");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

    my $name = "transportCert-" . $machineName . "-" . $securePort;
    my $params = "name=" . $name . "&" .
                  "certificate=" .
                      URI::Escape::uri_escape("$certificate") . "&" .
                  "xmlOutput=true" . "&" .
                  "sessionID=" . $session_id .  "&" .
                  "auth_hostname=" . $sdom_info->host . "&" .
                  "auth_port=" . $sdom_info->port;

    my $host = $tksinfo_url->host;
    my $port = $tksinfo_url->port;
    my $tmpfile = "/tmp/donepanel-$$";
    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        system("/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$db_password\" -v -r \"/tks/admin/tks/importTransportCert\" $host:$port > $tmpfile");
    } else {
        system("/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$token_pwd\" -v -r \"/tks/admin/tks/importTransportCert\" $host:$port > $tmpfile");
    }

    my $content = `cat $tmpfile`;
    system("rm $tmpfile");

    $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $content = $1;

    &PKI::RA::Wizard::debug_log("DonePanel: Response from TKS " . $content);
}

sub display
{
    my ($q) = @_;
        #         $symbol{systemType}  = "ra";
        #         $symbol{host}  = "chico";
        #         $symbol{port}  = "443";
    &PKI::RA::Wizard::debug_log("DonePanel: display");

    my $status = $::config->get("preop.done.status");
    if ($status eq "done") {
      return 1;
    }

    my $instDir = $::config->get("service.instanceDir");
    my $tokenname = $::config->get("preop.module.token");
    my $token_pwd = $::pwdconf->get($tokenname);
    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    if (($tokenname ne "") && ($tokenname ne "NSS Certificate DB")) {
      open(PWD_CONF, ">>$instDir/conf/password.conf");
      print PWD_CONF "$tokenname:$token_pwd\n";
      close (PWD_CONF);
    }

    # Add this RA's server certificate to the subsystems
    my $sdom = $::config->get("config.sdomainEEURL");
    my $cainfo = $::config->get("preop.cainfo.select");
    $cainfo =~ s/.* - //g;
    &register_ra($sdom, $cainfo, $::config->get("conn.ca1.servlet.addagent"), "CA");

    $::config->put("preop.done.status", "done");
    $::config->commit();

    # update httpd.conf
    open(TMP_HTTPD_CONF, ">$instDir/conf/httpd.conf.tmp");
    system( "chmod 00660 $instDir/conf/httpd.conf.tmp" );
    open(HTTPD_CONF, "<$instDir/conf/httpd.conf");
    while (<HTTPD_CONF>) {
        if (/^#\[ErrorDocument_404\]/) {
            print TMP_HTTPD_CONF "ErrorDocument 404 /404.html\n";
        } elsif (/^#\[ErrorDocument_500\]/) {
            print TMP_HTTPD_CONF "ErrorDocument 500 /500.html\n";
        } else {
          print TMP_HTTPD_CONF $_;
        }
    }
    close(HTTPD_CONF);
    close(TMP_HTTPD_CONF);

    # Create a copy of the original file which
    # preserves the original file permissions
    system( "cp -p $instDir/conf/httpd.conf.tmp $instDir/conf/httpd.conf" );

    # Remove the original file only if the backup copy was successful
    if( -e "$instDir/conf/httpd.conf" ) {
      system( "rm $instDir/conf/httpd.conf.tmp" );
    }

    # update nss.conf
    open(TMP_NSS_CONF, ">$instDir/conf/nss.conf.tmp");
    system( "chmod 00660 $instDir/conf/nss.conf.tmp" );
    open(NSS_CONF, "<$instDir/conf/nss.conf");
    while (<NSS_CONF>) {
        if (/^NSSNickname/) {
            print TMP_NSS_CONF "NSSNickname \"$nickname\"\n";
        } else {
          print TMP_NSS_CONF $_;
        }
    }
    close(NSS_CONF);
    close(TMP_NSS_CONF);

    # Create a copy of the original file which
    # preserves the original file permissions
    system( "cp -p $instDir/conf/nss.conf.tmp $instDir/conf/nss.conf" );

    # Remove the original file only if the backup copy was successful
    if( -e "$instDir/conf/nss.conf" ) {
      system( "rm $instDir/conf/nss.conf.tmp" );
    }

    &PKI::RA::Wizard::debug_log("DonePanel: Connecting to Security Domain");

    my $machineName = $::config->get("service.machineName");
    my $unsecurePort = $::config->get("service.unsecurePort");
    my $securePort = $::config->get("service.securePort");
    my $non_clientauth_securePort = $::config->get("service.non_clientauth_securePort");
    my $instanceID = $::config->get("service.instanceID");

    my $initDaemon = "pki-rad";
    my $restartCommand = "";
    if( $^O eq "linux" ) {
        $restartCommand = "systemctl restart $initDaemon\@$instanceID.service";
    } else {
        ## default case:  e. g. - ( $^O eq "solaris" )
        $restartCommand  = "/etc/init.d/$initDaemon restart $instanceID";
    }

    $::symbol{host}  = $machineName;
    $::symbol{unsecurePort}  = $unsecurePort;
    $::symbol{port}  = $securePort;
    $::symbol{non_clientauth_port}  = $non_clientauth_securePort;
    $::symbol{restartCommand}  = $restartCommand;
    $::symbol{instanceID}  = $instanceID;

    $::config->deleteSubstore("preop.");
    $::config->commit();

    ## Create an empty file that designates the fact that although
    ## this server instance has been configured, it has NOT yet
    ## been restarted!
    my $restart_server = "$instDir/conf/restart_server_after_configuration";
    system( "touch $restart_server" );
    system( "chmod 00660 $restart_server" );

    system("rm $instDir/conf/*.txt $instDir/conf/*.der");
    return 1;
}

1;
