##############################################################
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
# This script is to create a new instance of Token Processing
# Service within CS installation.
#
# To execute:
#   perl create.pl
#
##############################################################

use FindBin;

##############################################################
# Advance Options
##############################################################

my $hsm = "";                       # hardware token label (i.e. 'nFast')
my $hsm_ca = "";                    # hardware token label for CA certificate (i.e. 'nFast')
my $nickName = "Server-Cert";       # nickname

##############################################################
# Private
##############################################################
my $hsmLabel;
my $serverRoot;
my $instanceID;
my $serverID;
my $serverName;
my $port;
my $securePort;
my $uid;
my $gid;
my $tmpDir;
my $tpsDir;
my $tusHost;
my $tusPort;
my $tusRoot;
my $tusSuffix;
my $tusAgentCert;
my $caHost;
my $caPort;
my $drmHost;
my $drmPort;
my $serverKeyGen;
my $tksHost;
my $tksPort;
my $ldapHost;
my $ldapPort;
my $ldapRoot;
my $pathSep;
my $objExt;
my $libPrefix;

my $defaultUID = "root";
my $defaultServerRoot = "$FindBin::Bin";
$defaultServerRoot =~ s/\/bin\/cert\/tps\/setup//;
$defaultServerRoot =~ s/\/$//;
my $defaultServerID = "machine";
my $defaultServerName = "machine.fedora.com";
my $defaultInstanceID = "tps-machine";
my $defaultSuffix = "dc=machine,dc=fedora,dc=com";

sub PromptUser
{
  print ("************************************************\n");
  print ("Token Processing Service (TPS) Setup\n");
  print ("************************************************\n");
  print ("This script will assist you in setting up TPS.\n");
  print ("Before running this script, you should already \n");
  print ("install a certificate authority (CA), a token key \n");
  print ("service (TKS), an authentication directory and a token \n");
  print ("database.\n");
  print ("\n");
  print ("CA is responsible for issuing certificates while TKS \n");
  print ("ensures a secure channel between the client and \n");
  print ("the backend. User requests are authenticated against \n");
  print ("the authentication directory which contains user \n");
  print ("information. The token database collects statistics \n");
  print ("on token activities.\n");
  print ("\n");
  print ("The authentication database and the token database are \n");
  print ("regular directory server instances that can be created \n");
  print ("via Console.\n");
  print ("\n");
  print ("If you need other advanced options such as hardware \n");
  print ("token support, you need to modify the advanced option \n");
  print ("section of this script manually.\n");
  print ("\n");
  print ("************************************************\n");
  print ("GENERAL SETUP SECTION \n");
  print ("\n");
  print ("This script is about to create your TPS instance in your \n");
  print ("existing CS installation.\n");
  print ("************************************************\n");
  print ("\n");

ASK_PKI_INSTANCE_PATH:
  print ("Enter the path to the server root [$defaultServerRoot]: ");
  chomp ($serverRoot = <STDIN>);
  if ($serverRoot eq "") {
    $serverRoot = "$defaultServerRoot";
  }
  if ($serverRoot =~ /\/$/) {
    print ("Error: '$serverRoot' cannot end with '/'.\n");
    goto ASK_PKI_INSTANCE_PATH;
  }
  if (!(-d $serverRoot)) {
    print ("Error: '$serverRoot' directory does not exit.\n");
    goto ASK_PKI_INSTANCE_PATH;
  }
  if (!(-f "$serverRoot/admin-serv/config/adm.conf")) {
    print ("Error: '$serverRoot' directory does not contain $serverRoot/admin-serv/config/adm.conf.\n");
    goto ASK_PKI_INSTANCE_PATH;
  }

  # read some good parameters from adm.conf
  open(F, "$serverRoot/admin-serv/config/adm.conf");
  while (<F>) {
    if (/ldapHost:\s*(\S+)/) {
      $defaultServerName = $1;
    }
    if (/ldapStart:\s*slapd-(\S+)\//) {
      $defaultServerID = $1;
    }
  }
  close(F);

  open(F, "$serverRoot/admin-serv/config/magnus.conf");
  while (<F>) {
    if (/User (\S+)/) {
      $defaultUID = $1;
    }
  }
  close(F);

  $defaultSuffix = $defaultServerName;
  $defaultSuffix =~ s/\./,dc=/g;
  $defaultSuffix =~ s/^[^,]+,//;

ASK_TPS_ROOT:
  print ("Enter the path to the TPS release [$serverRoot/bin/cert/tps]: ");
  chomp ($tpsDir = <STDIN>);
  if ($tpsDir eq "") {
    $tpsDir = "$serverRoot/bin/cert/tps";
  }
  if (!(-d $tpsDir)) {
    print ("Error: '$tpsDir' directory does not exit.\n");
    goto ASK_TPS_ROOT;
  }
  if (!(-d "$tpsDir/config")) {
    print ("Error: '$tpsDir/config' directory does not exit.\n");
    goto ASK_TPS_ROOT;
  }

  print ("Enter the hostname of this machine [$defaultServerID]: ");
  chomp ($serverID = <STDIN>);
  if ($serverID eq "") {
    $serverID = "$defaultServerID";
  }
  print ("Enter the fully-qualified hostname of this machine [$defaultServerName]: ");
  chomp ($serverName = <STDIN>);
  if ($serverName eq "") {
    $serverName = "$defaultServerName";
  }

ASK_INSTANCE_ID:
  print ("Enter the instance ID of your new TPS instance [tps-$defaultServerID]: ");
  chomp ($instanceID = <STDIN>);
  if ($instanceID eq "") {
    $instanceID = "tps-$defaultServerID";
  }
  if (-d "$serverRoot/$instanceID") {
    print ("Error: '$serverRoot/$instanceID' directory already exist.\n");
    goto ASK_INSTANCE_ID;
  }

  # update nickName
  $nickName = "$nickName $instanceID";

  print ("\n");
  print ("************************************************\n");
  print ("SERVICE PORTS SECTION \n");
  print ("\n");
  print ("TPS listens on the following ports. Please make \n");
  print ("sure you specify unused ports.\n");
  print ("************************************************\n");
  print ("\n");

  print ("Enter the UID that TPS should be running as [$defaultUID]: ");
  chomp ($uid = <STDIN>);
  if ($uid eq "") {
    $uid = "$defaultUID";
  }

  my $defaultGID = $defaultUID;
  print ("Enter the GID that TPS should be running as [$defaultGID]: ");
  chomp ($gid = <STDIN>);
  if ($gid eq "") {
    $gid = "$defaultGID";
  }

ASK_EE_PORT:
  print ("Enter the end entity port number of your TPS [7888]: ");
  chomp ($port = <STDIN>);
  if ($port eq "") {
    $port = "7888";
  }
  if ($port eq "") {
    goto ASK_EE_PORT;
  }

ASK_AGENT_PORT:
  print ("Enter the agent port number of your TPS [7889]: ");
  chomp ($securePort = <STDIN>);
  if ($securePort eq "") {
    $securePort = "7889";
  }
  if ($securePort eq "") {
    goto ASK_AGENT_PORT;
  }

  print ("\n");
  print ("************************************************\n");
  print ("AUTHENTICATION (LDAP) DIRECTORY SECTION \n");
  print ("\n");
  print ("TPS verifies the user IDs and \n");
  print ("passwords against this LDAP database before executing \n");
  print ("requests from users.\n");
  print ("************************************************\n");
  print ("\n");

ASK_AUTH_HOST:
  print ("Enter the hostname of the authentication directory [$defaultServerName]: ");
  chomp ($ldapHost = <STDIN>);
  if ($ldapHost eq "") {
    $ldapHost = "$defaultServerName";
  }
  if ($ldapHost eq "") {
    goto ASK_AUTH_HOST;
  }

ASK_AUTH_PORT:
  print ("Enter the port number of the authentication directory [389]: ");
  chomp ($ldapPort = <STDIN>);
  if ($ldapPort eq "") {
    $ldapPort = "389";
  }
  if ($ldapPort eq "") {
    goto ASK_AUTH_PORT;
  }

ASK_AUTH_ROOT:
  print ("Enter the root suffix of the authentication directory [$defaultSuffix]: ");
  chomp ($ldapRoot = <STDIN>);
  if ($ldapRoot eq "") {
    $ldapRoot = "$defaultSuffix";
  }
  if ($ldapRoot eq "") {
    goto ASK_AUTH_ROOT;
  }

  print ("\n");
  print ("************************************************\n");
  print ("CA CONNECTION SECTION \n");
  print ("\n");
  print ("TPS submits certificate requests \n");
  print ("to CA for signing.\n");
  print ("************************************************\n");
  print ("\n");

ASK_PKI_CA_HOSTNAME:
  print ("Enter the hostname of the CA [$defaultServerName]: ");
  chomp ($caHost = <STDIN>);
  if ($caHost eq "") {
    $caHost = "$defaultServerName";
  }
  if ($caHost eq "") {
    goto ASK_PKI_CA_HOSTNAME;
  }

ASK_PKI_CA_PORT:
  print ("Enter the secure end entity port number of the CA [443]: ");
  chomp ($caPort = <STDIN>);
  if ($caPort eq "") {
    $caPort = "443";
  }
  if ($caPort eq "") {
    goto ASK_PKI_CA_PORT;
  }

  print ("\n");
  print ("************************************************\n");
  print ("TKS CONNECTION SECTION \n");
  print ("\n");
  print ("TPS obtains session keys from TKS \n");
  print ("for establishing secure channels.\n");
  print ("************************************************\n");
  print ("\n");

ASK_TKS_HOST:
  print ("Enter the hostname of the TKS [$defaultServerName]: ");
  chomp ($tksHost = <STDIN>);
  if ($tksHost eq "") {
    $tksHost = "$defaultServerName";
  }
  if ($tksHost eq "") {
    goto ASK_TKS_HOST;
  }

ASK_TKS_PORT:
  print ("Enter the secure agent port number of the TKS [8100]: ");
  chomp ($tksPort = <STDIN>);
  if ($tksPort eq "") {
    $tksPort = "8100";
  }
  if ($tksPort eq "") {
    goto ASK_TKS_PORT;
  }

  print ("\n");
  print ("Do you want to perform server-side key generation optionally [yes]: \n");
  chomp ($continue = <STDIN>);
  print ("\n");

  if ($continue eq "") {
    $continue = "yes";
  }
  if ($continue eq "yes") {
    $serverKeyGen = "true";

    print ("************************************************\n");
    print ("DRM CONNECTION SECTION \n");
    print ("\n");
    print ("TPS submits archival and recovery requests \n");
    print ("to DRM.\n");
    print ("************************************************\n");
    print ("\n");

ASK_DRM_HOST:
    print ("Enter the hostname of the DRM [$defaultServerName]: ");
    chomp ($drmHost = <STDIN>);
    if ($drmHost eq "") {
      $drmHost = "$defaultServerName";
    }
    if ($drmHost eq "") {
      goto ASK_DRM_HOST;
    }

ASK_DRM_PORT:
    print ("Enter the secure agent port number of the DRM [8100]: ");
    chomp ($drmPort = <STDIN>);
    if ($drmPort eq "") {
      $drmPort = "8100";
    }
    if ($drmPort eq "") {
      goto ASK_DRM_PORT;
    }
    print ("\n");
  } else {
    $serverKeyGen = "false";
  }

  print ("************************************************\n");
  print ("TOKEN DATABASE (LDAP) CONNECTION SECTION \n");
  print ("\n");
  print ("TPS sends statistics information to the database \n");
  print ("for auditing purposes.\n");
  print ("************************************************\n");
  print ("\n");

ASK_TUS_HOST:
  print ("Enter the hostname of the token database [$defaultServerName]: ");
  chomp ($tusHost = <STDIN>);
  if ($tusHost eq "") {
    $tusHost = "$defaultServerName";
  }
  if ($tusHost eq "") {
    goto ASK_TUS_HOST;
  }

ASK_TUS_PORT:
  print ("Enter the port number of the token database [3890]: ");
  chomp ($tusPort = <STDIN>);
  if ($tusPort eq "") {
    $tusPort = "3890";
  }
  if ($tusPort eq "") {
    goto ASK_TUS_PORT;
  }

ASK_TUS_ROOT:
  print ("Enter the root suffix of the token database [$defaultSuffix]: ");
  chomp ($tusRoot = <STDIN>);
  if ($tusRoot eq "") {
    $tusRoot = "$defaultSuffix";
  }
  if ($tusRoot eq "") {
    goto ASK_TUS_ROOT;
  }

ASK_TUS_PWD:
  print ("Enter the password of the directory manager: ");
  if (!&IsWindows()) {
    system("stty -echo");
  }
  chomp ($tusPass = <STDIN>);
  if (!&IsWindows()) {
    system("stty echo");
  }
  if ($tusPass eq "") {
    goto ASK_TUS_PWD;
  }
        
  if (&IsWindows()) {
    $tmpDir = "c:\\temp";
  } else {
    $tmpDir = "/tmp";
  }
  print ("\n");
}

sub ToContinue
{
  do {
    print ("Please enter 'proceed' to continue.\n");
    chomp ($continue = <STDIN>);
  } while ($continue ne "proceed");
}

sub CreateSecurityDatabase
{
  print ("This program is about to create the NSS certificate DB.\n");
  &ToContinue();
  print ("\n");

  &CertUtil_CreateDatabase($serverRoot, "$instanceID-$serverID-");
  print ("\n");

  print ("This program is about to generate the certificate request.\n");
  &ToContinue();
  print ("\n");

ASK_SERVER_CERT:
  &CertUtil_GenerateCSR($serverRoot, "$instanceID-$serverID-", 
     $hsm, "CN=" . $serverName);
  print ("\n");

  print ("Please submit the certificate request to the CA's Manual TPS Server Certificate Enrollment profile for signing.\n");
  print ("Note that correct OIDs (i.e. 1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2 and 1.3.6.1.5.5.7.3.4) must be populated in the\n");
  print ("extended key usage extension of the certificate.\n");
  print ("In addition, this certificate must be added to \n");
  print ("CA and TKS as trusted agent.\n");
  print ("\n");
  print ("This program is about to import the TPS system certificate.\n");
  print ("Please paste in your certificate (including header and footer).\n");
  print ("\n");
  my $serverCert = &PromptCertificate();
  &CertUtil_ImportServerCert($serverRoot, "$instanceID-$serverID-", 
    $hsm, $nickName, $serverCert);
  print ("\n");

  &CertUtil_Print($serverRoot, "$instanceID-$serverID-", $hsm, $nickName);
  print ("\n");
  print ("Is the server certificate correct [yes]: \n");
  chomp ($continue = <STDIN>);
  print ("\n");
  if ($continue eq "") {
    $continue = "yes";
  }
  if ($continue eq "no") {
    goto ASK_SERVER_CERT;
  }

  $i = 0;
  print ("This program is about to import one or more CA certificates.\n");
  while (1) {
ASK_AGAIN:
    print ("Do you have CA certificate to import [yes]: \n");
    chomp ($continue = <STDIN>);
    print ("\n");
    if ($continue eq "") {
      $continue = "yes";
    }
    if ($continue eq "no") {
      goto DONE;
    }
    print ("Please paste in your CA certificate (including header and footer).\n");
    print ("\n");
    my $caCert = &PromptCertificate();
    &CertUtil_ImportCACert($serverRoot, "$instanceID-$serverID-", 
        $hsm_ca, "caCert$i $instanceID", "$caCert");
    print ("\n");

    &CertUtil_Print($serverRoot, "$instanceID-$serverID-", $hsm_ca, "caCert$i $instanceID");
    print ("\n");
    print ("Is the CA certificate correct [yes]: \n");
    chomp ($continue = <STDIN>);
    print ("\n");
    if ($continue eq "") {
      $continue = "yes";
    }
    if ($continue eq "no") {
      &CertUtil_Delete($serverRoot, "$instanceID-$serverID-", $hsm, "caCert$i $instanceID");
      goto ASK_AGAIN;
    }
    $i++;
  }

DONE:

  print ("The following shows all imported certificates.\n");
  &CertUtil_List($serverRoot, "$instanceID-$serverID-", $hsm);
  print ("\n");
  &ToContinue();
}

sub PromptCertificate
{
  my $startCert = 0;
  my $cert;
  while (1) {
    chomp ($continue = <STDIN>);
    if ($continue eq "-----END CERTIFICATE-----") {
      $cert .= $continue . "\n";
      goto DONE;
    }
    if ($startCert == 1) {
      $cert .= $continue . "\n";
    }
    if ($continue eq "-----BEGIN CERTIFICATE-----") {
      $startCert = 1;
      $cert .= $continue . "\n";
    }
  }
DONE:
  return $cert;
}

sub Main
{
  if (&IsWindows()) {
    $pathSep = ";";
    $objExt = ".dll";
    $libPrefix = "";
  } else {
    $pathSep = ":";
    $objExt = ".so";
    $libPrefix = "lib";
  }

  if ($hsm eq "") {
    $hsmLabel = "";
  } else {
    $hsmLabel = $hsm . ":";
  }

  &PromptUser();

  print ("************************************************\n");
  print ("TPS INSTANCE CREATION \n");
  print ("************************************************\n");
  print ("This program is about to create the TPS instance.\n");
  print ("If there is any error, please ctrl-C to exit and ");
  print ("restart the process.\n");
  print ("\n");
  &ToContinue();
  print ("\n");

  &CreateInstanceDir();
  &CopyTemplates();
  &PopulateTPSTemplates();
  print ("\n");

  print ("************************************************\n");
  print ("SECURITY DATABASE CREATION (OPTIONAL) \n");
  print ("\n");
  print ("Keys and certificates will be stored in the security\n");
  print ("databases.\n");
  print ("************************************************\n");

  print ("This program is about to create the security databases.\n");

ASK_AGAIN:
  print ("Do you want to create the security databases automatically [yes]: \n");
  chomp ($continue = <STDIN>);
  print ("\n");

  if ($continue eq "") {
    $continue = "yes";
  }
  if ($continue eq "no") {
    print ("Please place your own security databases ");
    print ("in $serverRoot/alias/$instanceID-$serverID-*.db\n");
    print ("\n");
  } elsif ($continue eq "yes") {
    &CreateSecurityDatabase();
  } else {
    goto ASK_AGAIN;
  }

  print ("************************************************\n");
  print ("TOKEN DATABASE POPULATION (OPTIONAL) \n");
  print ("\n");
  print ("Token database's Schema and default structure will be setup.\n");
  print ("Your first authorized agent certificate will be \n");
  print ("imported into the database. TPS agent port can \n");
  print ("be accessed by browser that contain the authorized \n");
  print ("agent certificate.\n");
  print ("************************************************\n");
  print ("This program is about to populate the token database.\n");

ASK_AGAIN2:
  print ("Do you want to populate the token database automatically [yes]: \n");
  chomp ($continue = <STDIN>);
  print ("\n");
  if ($continue eq "") {
    $continue = "yes";
  }
  if ($continue eq "no") {
    print ("Please populate the token database manually.\n");
  } elsif ($continue eq "yes") {
    &PopulateTUS();
  } else {
    goto ASK_AGAIN2;
  }

  print ("\n");
  print ("************************************************\n");
  print ("SETUP IS DONE \n");
  print ("************************************************\n");
  print ("You should manually start your TPS by \n");
  print ("running the start script in the TPS instance.\n");
  print ("\n");
  print ("  $serverRoot/$instanceID/start\n");
  print ("\n");
  print ("You can use your ESC client to access TPS's \n");
  print ("end entity port.\n");
  print ("\n");
  print ("  http://$serverName:$port/nk_service\n");
  print ("\n");
  print ("You can use your browser to access TPS's \n");
  print ("agent port for agent/administrator operations.\n");
  print ("\n");
  print ("  https://$serverName:$securePort/tus\n");
  print ("\n");
  print ("\n");
}

sub CopyTemplate
{
  my ($from, $to) = @_;

  print "Copying $from to $to ...\n";
  open(IN, "<$from");
  open(OUT, ">$to");
  while (<IN>) {
    s/\[PKI_INSTANCE_PATH\]/$serverRoot/g;
    s/\[INSTANCE_ID\]/$instanceID/g;
    s/\[PKI_HOSTNAME\]/$serverName/g;
    s/\[PORT\]/$port/g;
    s/\[PKI_SECURE_PORT\]/$securePort/g;
    s/\[NICKNAME\]/$nickName/g;
    s/\[USERID\]/$uid/g;
    s/\[GROUPID\]/$gid/g;
    s/\[TMP_DIR\]/$tmpDir/g;
    s/\[TPS_DIR\]/$tpsDir/g;
    s/\[LIB_PREFIX\]/$libPrefix/g;
    s/\[OBJ_EXT\]/$objExt/g;
    s/\[HSM_LABEL\]/$hsmLabel/g;
    s/\[TUS_AGENT_CERT\]/$tusAgentCert/g;
    s/\[TUS_HOST\]/$tusHost/g;
    s/\[TUS_PORT\]/$tusPort/g;
    s/\[TUS_ROOT\]/$tusRoot/g;
    s/\[TUS_PASS\]/$tusPass/g;
    s/\[PKI_CA_HOSTNAME\]/$caHost/g;
    s/\[PKI_CA_PORT\]/$caPort/g;
    s/\[DRM_HOST\]/$drmHost/g;
    s/\[DRM_PORT\]/$drmPort/g;
    s/\[SERVER_KEYGEN\]/$serverKeyGen/g;
    s/\[TKS_HOST\]/$tksHost/g;
    s/\[TKS_PORT\]/$tksPort/g;
    s/\[LDAP_HOST\]/$ldapHost/g;
    s/\[LDAP_PORT\]/$ldapPort/g;
    s/\[LDAP_ROOT\]/$ldapRoot/g;
    s/\[PROCESS_ID\]/$$/g;
    print OUT $_;
  }
  close(OUT);
  close(IN);
}

sub IsWindows
{
  if ($^O eq "MSWin32") {
    return 1;
  } else {
    return 0;
  }
}

sub CopyFiles
{
  my ($from, $to) = @_;

  print("Copying files from $from to $to ...\n");
  if (&IsWindows()) {
    system("xcopy /E /I /Q $from $to");
  } else {
    system("cp -R $from $to");
  }
}

sub PopulateTPSTemplates
{
  &CopyTemplate("$tpsDir/config/CS.cfg", 
    "$serverRoot/$instanceID/config/CS.cfg");
  chmod(00660, "$serverRoot/$instanceID/config/CS.cfg");

  print "Creating $serverRoot/cgi-bin ...\n";
  mkdir ("$serverRoot/cgi-bin", 0755);

  &CopyFiles("$tpsDir/forms/esc", "$serverRoot/cgi-bin");
  &CopyFiles("$tpsDir/forms/tus", "$serverRoot/cgi-bin");
}

sub PopulateTUS
{
  print ("Please paste in your TPS Agent certificate (including header and footer).\n");
  print ("\n");
  my $cert = &PromptCertificate();
  $cert =~ s/-----BEGIN CERTIFICATE-----\s*//g;
  $cert =~ s/-----END CERTIFICATE-----\s*//g;
  $cert =~ s/\s*//g;

  $tusAgentCert = $cert;

  print ("\n");
  &ToContinue();
  print ("\n");

  open(F1, "$tpsDir/scripts/addVLVIndexes.ldif");
  open(F2, ">$serverRoot/$instanceID/config/addVLVIndexes.ldif");
  while (<F1>) {
    s/{rootSuffix}/$tusRoot/;
    print F2 $_;
  }

  close(F1);
  close(F2);
  &LDAPAdd("$serverRoot/$instanceID/config/addVLVIndexes.ldif");

  &CopyTemplate("$tpsDir/scripts/schemaMods.ldif", 
    "$serverRoot/$instanceID/config/schemaMods.ldif");
  &CopyTemplate("$tpsDir/scripts/addTokens.ldif", 
    "$serverRoot/$instanceID/config/addTokens.ldif");
  &CopyTemplate("$tpsDir/scripts/addIndexes.ldif", 
    "$serverRoot/$instanceID/config/addIndexes.ldif");
  &CopyTemplate("$tpsDir/scripts/addAgents.ldif", 
    "$serverRoot/$instanceID/config/addAgents.ldif");

  &LDAPModify("$serverRoot/$instanceID/config/schemaMods.ldif");
  &LDAPAdd("$serverRoot/$instanceID/config/addIndexes.ldif");
  &LDAPAdd("$serverRoot/$instanceID/config/addTokens.ldif");
  &LDAPAdd("$serverRoot/$instanceID/config/addAgents.ldif");
}

sub CopyTemplates
{
  &CopyTemplate("./templates/start", "$serverRoot/$instanceID/start");
  chmod(0755, "$serverRoot/$instanceID/start");
  &CopyTemplate("./templates/stop", "$serverRoot/$instanceID/stop");
  chmod(0755, "$serverRoot/$instanceID/stop");
  &CopyTemplate("./templates/config/contexts.properties", 
    "$serverRoot/$instanceID/config/contexts.properties");
  &CopyTemplate("./templates/config/jvm12.conf", 
    "$serverRoot/$instanceID/config/jvm12.conf");
  &CopyTemplate("./templates/config/magnus.conf", 
    "$serverRoot/$instanceID/config/magnus.conf");
  &CopyTemplate("./templates/config/magnus.conf.clfilter", 
    "$serverRoot/$instanceID/config/magnus.conf.clfilter");
  &CopyTemplate("./templates/config/mime.types", 
    "$serverRoot/$instanceID/config/mime.types");
  &CopyTemplate("./templates/config/obj.conf", 
    "$serverRoot/$instanceID/config/obj.conf");
  &CopyTemplate("./templates/config/obj.conf.clfilter", 
    "$serverRoot/$instanceID/config/obj.conf.clfilter");
  &CopyTemplate("./templates/config/rules.properties", 
    "$serverRoot/$instanceID/config/rules.properties");
  &CopyTemplate("./templates/config/server.dtd", 
    "$serverRoot/$instanceID/config/server.dtd");
  &CopyTemplate("./templates/config/server.xml", 
    "$serverRoot/$instanceID/config/server.xml");
  &CopyTemplate("./templates/config/server.xml.clfilter", 
    "$serverRoot/$instanceID/config/server.xml.clfilter");
  &CopyTemplate("./templates/config/servlets.properties", 
    "$serverRoot/$instanceID/config/servlets.properties");
  &CopyTemplate("./templates/config/web-apps.xml", 
    "$serverRoot/$instanceID/config/web-apps.xml");
  &CopyTemplate("./templates/config/web-apps.xml.clfilter", 
    "$serverRoot/$instanceID/config/web-apps.xml.clfilter");
}

sub CreateInstanceDir
{
  print "Creating $serverRoot/$instanceID ...\n";
  mkdir ("$serverRoot/$instanceID", 0755);

  print "Creating $serverRoot/$instanceID/config ...\n";
  mkdir ("$serverRoot/$instanceID/config", 0755);

  print "Creating $serverRoot/$instanceID/logs ...\n";
  mkdir ("$serverRoot/$instanceID/logs", 0755);
}

sub getPath
{
  if (&IsWindows()) {
    return $ENV{PATH};
  } else {
    return $ENV{LD_LIBRARY_PATH};
  }
}

sub setPath
{
  my ($path) = @_;

  if (&IsWindows()) {
    $ENV{PATH} = $path;
  } else {
    $ENV{LD_LIBRARY_PATH} = $path;
  }
}

sub CertUtil_CreateDatabase
{
  my ($serverRoot, $prefix) = @_;
	
  $OrgPath = &getPath();
  &setPath($serverRoot . "/bin/cert/lib"  . $pathSep . $OrgPath);

  system("$serverRoot/bin/cert/tools/certutil -N -d $serverRoot/alias -P $prefix");

  &setPath($OrgPath);
}

sub CertUtil_GenerateCSR
{
  my ($serverRoot, $prefix, $token, $subject) = @_;

  $OrgPath = &getPath();
  &setPath($serverRoot . "/bin/cert/lib" . $pathSep . $OrgPath);

  system("$serverRoot/bin/cert/tools/certutil -R -d $serverRoot/alias -P $prefix -h '$token' -s '$subject' -a");

  &setPath($OrgPath);
}

sub CertUtil_List
{
  my ($serverRoot, $prefix, $token) = @_;

  $OrgPath = &getPath();
  &setPath($serverRoot . "/bin/cert/lib" . $pathSep . $OrgPath);

  system("$serverRoot/bin/cert/tools/certutil -L -d $serverRoot/alias -P $prefix -h '$token'");

  &setPath($OrgPath);
}

sub CertUtil_Print
{
  my ($serverRoot, $prefix, $token, $nickName) = @_;

  $OrgPath = &getPath();
  &setPath($serverRoot . "/bin/cert/lib" . $pathSep . $OrgPath);

  if ($token ne "") {
    #57616 - certutil is not being consistent, nickname 
    #        requires token name for no reason.
    system("$serverRoot/bin/cert/tools/certutil -L -d $serverRoot/alias -P $prefix -h '$token' -n '$token:$nickName'");
  } else {
    system("$serverRoot/bin/cert/tools/certutil -L -d $serverRoot/alias -P $prefix -h '$token' -n '$nickName'");
  }

  &setPath($OrgPath);
}

sub CertUtil_Delete
{
  my ($serverRoot, $prefix, $token, $nickName) = @_;

  $OrgPath = &getPath();
  &setPath($serverRoot . "/bin/cert/lib" . $pathSep . $OrgPath);

  system("$serverRoot/bin/cert/tools/certutil -D -d $serverRoot/alias -P $prefix -h '$token' -n '$nickName'");

  &setPath($OrgPath);
}

sub CertUtil_ImportServerCert
{
  my ($serverRoot, $prefix, $token, $nickName, $cert) = @_;

  $OrgPath = &getPath();
  &setPath($serverRoot . "/bin/cert/lib" . $pathSep . $OrgPath);

  open(F, "|$serverRoot/bin/cert/tools/certutil -A -d $serverRoot/alias -P $prefix -h '$token' -n '$nickName' -t 'u,u,u' -a");
  print F $cert;
  close(F);

  &setPath($OrgPath);
}

sub CertUtil_ImportCACert
{
  my ($serverRoot, $prefix, $token, $nickName, $cert) = @_;

  $OrgPath = &getPath();
  &setPath($serverRoot . "/bin/cert/lib" . $pathSep . $OrgPath);

  open(F, "|$serverRoot/bin/cert/tools/certutil -A -d $serverRoot/alias -P $prefix -h '$token' -n '$nickName' -t 'CT,CT,CT' -a");
  print F $cert;
  close(F);

  &setPath($OrgPath);
}

sub LDAPModify
{
  my ($file) = @_;

  $OrgPath = &getPath();
  &setPath($serverRoot . "/shared/lib" . $pathSep . $OrgPath);

  system("$serverRoot/shared/bin/ldapmodify -x -h '$tusHost' -p '$tusPort' -D 'cn=directory manager' -w '$tusPass' -f '$file'");

  &setPath($OrgPath);
}

sub LDAPAdd
{
  my ($file) = @_;

  $OrgPath = &getPath();
  &setPath($serverRoot . "/shared/lib" . $pathSep . $OrgPath);

  system("$serverRoot/shared/bin/ldapmodify -x -h '$tusHost' -p '$tusPort' -D 'cn=directory manager' -w '$tusPass' -a -f '$file'");

  &setPath($OrgPath);
}

&Main();
