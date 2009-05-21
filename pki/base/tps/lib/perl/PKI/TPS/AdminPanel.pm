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
use URI::Escape;

package PKI::TPS::AdminPanel;
$PKI::TPS::AdminPanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&is_panel_done;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(14);
    $self->{"getName"} = &PKI::TPS::Common::r("Administrator");
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
    &PKI::TPS::Wizard::debug_log("AdminPanel: validate");
    return 1;
}


sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("AdminPanel: update");

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
#    my $cainfo = $::config->get("preop.cainfo.select");

    # Admin Certificate should be obtained from the ca selected in the 
    # name panel. If name panel use External CA, the admin certificate
    # will be issued by the security domain CA.
    my $cainfo = $::config->get("preop.ca.url");
    &PKI::TPS::Wizard::debug_log("AdminPanel: preop.ca.url=$cainfo");
    if ($cainfo eq "" || $cainfo =~ /:$/) {
      $cainfo = $::config->get("config.sdomainEEURL");
      &PKI::TPS::Wizard::debug_log("AdminPanel: config.sdomainEEURL=$cainfo");
    }
    &PKI::TPS::Wizard::debug_log("AdminPanel: Connecting to CA: $cainfo");
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

    my $requestor_name = "TPS-" . $machineName . "-" . $securePort;

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
    &PKI::TPS::Wizard::debug_log("req = " . $content);

    $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
    $content = $1;

    # create user in internal database
    &PKI::TPS::Wizard::debug_log("AdminPanel: Creating user in internal database");
    # use scripts/addAgents.ldif

    my $parser = XML::Simple->new();
    my $response = $parser->XMLin($content);
    my $admincert = $response->{Requests}->{Request}->{b64};
    &PKI::TPS::Wizard::debug_log("AdminPanel: admincert " . $admincert);

    my $ldap_host = $::config->get("preop.database.host");
    my $ldap_port = $::config->get("preop.database.port");
    my $basedn = $::config->get("preop.database.basedn");
    my $binddn = $::config->get("preop.database.binddn");
#    my $bindpwd = $::config->get("tokendb.bindPass");
    my $bindpwd = `grep \"tokendbBindPass:\" \"$instanceDir/conf/password.conf\" | cut -c17-`;
    $bindpwd =~ s/\n$//g;

    my $tmp = "/tmp/addAgents-$$.ldif";

    my $flavor = `pkiflavor`;
    $flavor =~ s/\n//g;

    my $mozldap_path = "/usr/lib/mozldap";
    my $arch = `pkiarch`;
    $arch =~ s/\n//g;
    if ($arch eq "x86_64") {
      $mozldap_path = "/usr/lib64/mozldap";
    } elsif ($arch eq "sparcv9") {
      $mozldap_path = "/usr/lib/sparcv9/mozldap6";
    }

    $admincert =~ s/\//\\\//g;
    system("sed -e 's/\$TOKENDB_ROOT/$basedn/' " .
              "-e 's/\$TOKENDB_AGENT_PWD/$password/' " .
              "-e 's/\$TOKENDB_AGENT_CERT/$admincert/' " .
              "/usr/share/$flavor/tps/scripts/addAgents.ldif > $tmp");
    system("$mozldap_path/ldapmodify -h '$ldap_host' -p '$ldap_port' -D '$binddn' " .
              "-w '$bindpwd' -a " .
              "-f '$tmp'");
    system("rm $tmp");

    my $reqid = $response->{Requests}->{Request}->{Id};
    $::config->put("preop.admincert.requestId.0", $reqid);
    my $sn = $response->{Requests}->{Request}->{serialno};
    $::config->put("preop.admincert.serialno.0", $sn);
    $::config->put("preop.adminpanel.done", "true");
    $::config->commit();

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("AdminPanel: display");
    $::symbol{admin_uid} = "admin";
    $::symbol{admin_name} = "TPS Administrator";
    $::symbol{admin_email} = "";
    $::symbol{admin_pwd} = "";
    $::symbol{admin_pwd_again} = "";
    $::symbol{import} = "true";
    my $domain_name = $::config->get("preop.securitydomain.name");
    $::symbol{securityDomain} = $domain_name;

    return 1;
}

sub is_panel_done
{
   return $::config->get("preop.adminpanel.done");
}


1;
