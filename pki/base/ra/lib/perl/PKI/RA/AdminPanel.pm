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
use URI::Escape;
use DBI;

package PKI::RA::AdminPanel;
$PKI::RA::AdminPanel::VERSION = '1.00';

use PKI::RA::BasePanel;
our @ISA = qw(PKI::RA::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::RA::Common::no;
    $self->{"getPanelNo"} = &PKI::RA::Common::r(14);
    $self->{"getName"} = &PKI::RA::Common::r("Administrator");
    $self->{"vmfile"} = "adminpanel.vm";
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
    &PKI::RA::Wizard::debug_log("AdminPanel: validate");
    return 1;
}


sub update
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("AdminPanel: update");

    my $uid = $q->param("uid");
    my $name = $q->param("name");
    my $email = $q->param("email");
    my $password = $q->param("__pwd");
    my $password_again = $q->param("__admin_password_again");

    my $cert_request = $q->param("cert_request");
    my $subject = $q->param("subject");
    my $profile_id = $q->param("profileId");
    my $cert_request_type = $q->param("cert_request_type");

    $cert_request =~ s/%0D%0A//g; # remove carraige return

    # submit request to CA

    # Admin Certificate should be obtained from the ca selected in the 
    # name panel. If name panel use External CA, the admin certificate
    # will be issued by the security domain CA.
    my $cainfo = $::config->get("preop.ca.url");
    &PKI::RA::Wizard::debug_log("AdminPanel: preop.ca.url=$cainfo");
    if ($cainfo eq "" || $cainfo =~ /:$/) {
      $cainfo = $::config->get("config.sdomainEEURL");
      &PKI::RA::Wizard::debug_log("AdminPanel: config.sdomainEEURL=$cainfo");
    }
    &PKI::RA::Wizard::debug_log("AdminPanel: Connecting to CA: $cainfo");
    my $cainfo_url = new URI::URL($cainfo);
    my $sdom = $::config->get("config.sdomainEEURL");
    my $sdom_url = new URI::URL($sdom);

    my $machineName = $::config->get("service.machineName");
    my $securePort = $::config->get("service.securePort");
    my $session_id = $::config->get("preop.sessionID");

    my $tokenname = $::config->get("preop.module.token");
    my $token_pwd = $::pwdconf->get($tokenname);
    my $nickname = $::config->get("preop.cert.sslserver.nickname");
    my $instanceID = $::config->get("service.instanceID");
    my $instanceDir = $::config->get("service.instanceDir");
    my $db_password = `grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

    my $requestor_name = "RA-" . $machineName . "-" . $securePort;

    my $params = "profileId=" . $profile_id . "&" .
                  "requestor_name=" . $requestor_name . "&" .
                  "cert_request_type=" . $cert_request_type . "&" .
                  "subject=" . $subject . "&" .
                  "cert_request=" . 
                      URI::Escape::uri_escape("$cert_request") . "&" .
                  "xmlOutput=true" . "&" .
                  "sessionID=" . $session_id .  "&" .
                  "auth_hostname=" . $sdom_url->host . "&" .
                  "auth_port=" . $sdom_url->port;

    my $ca_host = $cainfo_url->host;
    my $https_ee_port = $cainfo_url->port;
    my $content = "";
    my $tmpfile = "/tmp/admin-$$";
    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        system("/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$nickname\" -r \"/ca/ee/ca/profileSubmit\" $ca_host:$https_ee_port > $tmpfile");
        $content = `cat $tmpfile`;
    } else {
        system("/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$token_pwd\" -v -n \"$nickname\" -r \"/ca/ee/ca/profileSubmit\" $ca_host:$https_ee_port > $tmpfile");
        $content = `cat $tmpfile`;
    }
    system("rm $tmpfile");
    &PKI::RA::Wizard::debug_log("req = " . $content);

    $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $content = $1;

    # create user in internal database
    &PKI::RA::Wizard::debug_log("AdminPanel: Creating user in internal database");
    # use scripts/addAgents.ldif

    my $parser = XML::Simple->new();
    my $response = $parser->XMLin($content);
    my $admincert = $response->{Requests}->{Request}->{b64};
    &PKI::RA::Wizard::debug_log("AdminPanel: admincert " . $admincert);

    # create local database
    my $dbh = DBI->connect(
                "dbi:SQLite:dbname=$instanceDir/conf/dbfile","","");
    my $insert = "insert into users (" .
                      "uid" . "," .
                      "name" . "," .
                      "password" . "," .
                      "email" . "," .
                      "certificate" .
                    ") values (" .
                       $dbh->quote($uid) . "," .
                       $dbh->quote($name) . "," .
                       $dbh->quote($password) . "," .
                       $dbh->quote($email) . "," .
                       $dbh->quote($admincert) .
                    ")";
    $dbh->do($insert);
    $insert = "insert into roles (" .
                      "uid" . "," .
                      "gid" .
                    ") values (" .
                       $dbh->quote($uid) . "," .
                       $dbh->quote("administrators") .
                    ")";
    $dbh->do($insert);
    $insert = "insert into roles (" .
                      "uid" . "," .
                      "gid" .
                    ") values (" .
                       $dbh->quote($uid) . "," .
                       $dbh->quote("agents") .
                    ")";
    $dbh->do($insert);
    $dbh->disconnect();

    my $reqid = $response->{Requests}->{Request}->{Id};
    $::config->put("preop.admincert.requestId.0", $reqid);
    my $sn = $response->{Requests}->{Request}->{serialno};
    $::config->put("preop.admincert.serialno.0", $sn);

    # update email address
    $::config->put("request.agent.create_request.1.mailTo", $email);
    $::config->put("request.scep.create_request.1.mailTo", $email);
    $::config->put("request.server.create_request.1.mailTo", $email);
    $::config->put("request.user.create_request.1.mailTo", $email);

    $::config->commit();

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("AdminPanel: display");
    $::symbol{admin_uid} = "admin";
    $::symbol{admin_name} = "RA Administrator";
    $::symbol{admin_email} = "";
    $::symbol{admin_pwd} = "";
    $::symbol{admin_pwd_again} = "";
    $::symbol{import} = "true";
    my $domain_name = $::config->get("preop.securitydomain.name");
    $::symbol{securityDomain} = $domain_name;

    return 1;
}

1;
