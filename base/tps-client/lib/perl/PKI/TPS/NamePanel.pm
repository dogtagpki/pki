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
use FileHandle;
use PKI::TPS::GlobalVar;
use PKI::TPS::Common;
use PKI::TPS::CertInfo;
use URI::URL;
use URI::Escape;

package PKI::TPS::NamePanel;
$PKI::TPS::NamePanel::VERSION = '1.00';

use PKI::TPS::BasePanel;
our @ISA = qw(PKI::TPS::BasePanel);
our $cert_req_header="-----BEGIN NEW CERTIFICATE REQUEST-----";
our $cert_req_footer="-----END NEW CERTIFICATE REQUEST-----";
our $cert_header="-----BEGIN CERTIFICATE-----";
our $cert_footer="-----END CERTIFICATE-----";

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&is_panel_done;
    $self->{"getPanelNo"} = &PKI::TPS::Common::r(12);
    $self->{"getName"} = &PKI::TPS::Common::r("Subject Names");
    $self->{"vmfile"} = "namepanel.vm";
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
    &PKI::TPS::Wizard::debug_log("NamePanel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("NamePanel: update");
    my $instanceDir =  $::config->get("service.instanceDir");

    my $count = $q->param('urls');

    &PKI::TPS::Wizard::debug_log("NamePanel: update - selected ca= $count");

    my $host = "";
    my $https_ee_port = "";

    my $useExternalCA = "off";
    if ($count =~ /http/) {
      my $info = new URI::URL($count);
      $host = $info->host;
      $https_ee_port = $info->port;
    } else {
      $host = $::config->get("preop.securitydomain.ca$count.host");
      if ($host eq "") {
          $useExternalCA = "on";
      } else {
          $https_ee_port = $::config->get("preop.securitydomain.ca$count.secureport");
          &PKI::TPS::Wizard::debug_log("NamePanel: update - host= $host, https_ee_port= $https_ee_port");
      }
    }
    $::config->put("preop.certenroll.useExternalCA", $useExternalCA);

    $::config->put("preop.ca.url", "https://" . $host . ":" . $https_ee_port);

    my $tokenname = $::config->get("preop.module.token");
    &PKI::TPS::Wizard::debug_log("NamePanel: update got token name = $tokenname");
    my $hw;
    my $tk;

    if (($tokenname eq "") || ($tokenname eq "NSS Certificate DB")) {
        $hw = "";
        $tk = "";
    } else {
        $hw = "-h $tokenname";
        $tk = $tokenname.":";
    }

    # is nickname changed because of token (hardware) selection?
    my $changed = "false";
    foreach my $certtag (@PKI::TPS::Wizard::certtags) {
        &PKI::TPS::Wizard::debug_log("NamePanel: update begins for certag= $certtag");
        my $cert_dn = $q->param($certtag);
        $::config->put("preop.cert.".$certtag.".dn", $cert_dn);
        $::config->commit();

        my $sslnickname = $::config->get("preop.cert.sslserver.nickname");
        my $nickname = $q->param($certtag . "_nick");
        if ($nickname ne "") {
            &PKI::TPS::Wizard::debug_log("NamePanel: update nickname for $certtag set to $nickname");
                &PKI::TPS::Wizard::debug_log("NamePanel: update nickname for $certtag being updated in config file");
                $::config->put("preop.cert.".$certtag.".nickname", $nickname);
                $::config->commit();
        } else {
            $nickname = $::config->get("preop.cert.$certtag.nickname");
            if ($nickname eq "") {
                $nickname = "TPS ".$certtag." cert";
                &PKI::TPS::Wizard::debug_log("NamePanel: update nickname not found for $certtag  -- try $nickname");
            }
        }

        my $cert_request = $::config->get("preop.cert.$certtag.certreq");
        if ($cert_request ne "") {
            &PKI::TPS::Wizard::debug_log("NamePanel: update do not generate new keys");
            goto GEN_CERT;
        }
        &PKI::TPS::Wizard::debug_log("NamePanel: update generate new keys");

        # =====generate requests========
        #   getting new request should void old cert
        my $file= "$instanceDir/conf/".$certtag."_cert.txt";
        my $tmp = `rm $file`;

        &PKI::TPS::Wizard::debug_log("NamePanel: retrieving $tokenname from pwdconf");
        my $token_pwd = $::pwdconf->get($tokenname);
        &PKI::TPS::Wizard::debug_log("NamePanel: creating pwfile");
        open FILE, ">$instanceDir/conf/.pwfile";
        system( "chmod 00660 $instanceDir/conf/.pwfile" );
        $token_pwd  =~ s/\n//g;
        print FILE $token_pwd;
        close FILE;

        my $keytype = $::config->get("preop.cert.$certtag.keytype");
        if ($keytype eq "") {
            $keytype = "rsa";
        }

        my $select = $::config->get("preop.cert.$certtag.keysize.select");

        my $keysize;

        if ($keytype eq "rsa") {
            $keysize = 2048;
        } elsif ($keytype eq "ecc") {
            $keysize = "nistp256";
        }

        if (($select eq "") || ($select eq "default")) {
            my $size = $::config->get("preop.cert.$certtag.keysize.size");
            if ($size ne "") {
                $keysize = $size;
            }
        } else {
            my $size = $::config->get("preop.cert.$certtag.keysize.customsize");
            if ($size ne "") {
                $keysize = $size;
            }
        }

        &PKI::TPS::Wizard::debug_log("NamePanel: update got key type $keytype");
        my $req = "";
        my $debug_req;
        my $filename = "/tmp/random.$$";
        `dd if\=/dev/urandom of\=\"$filename\" count\=256 bs\=1`;
        if ($keytype eq "rsa") {
            #XXX temporary
            &PKI::TPS::Wizard::debug_log("NamePanel: update "."certutil -R -s $cert_dn -k $keytype -g $keysize -d $instanceDir/alias $hw -f $instanceDir/conf/.pwfile -a -z $filename");
            my $tmpfile = "/tmp/req$$";
            system("certutil -R -s \"$cert_dn\" -k $keytype -g $keysize -d $instanceDir/alias $hw -f $instanceDir/conf/.pwfile -a -z $filename > $tmpfile");
            $req = `cat $tmpfile`;
            system("rm $tmpfile");
        } elsif ($keytype eq "ecc") {
            my $tmpfile = "/tmp/req$$";
            # try first without specific flags
            system("certutil -d $instanceDir/alias $hw -f $instanceDir/conf/.pwfile -R -s \"$cert_dn\" -k ec -q $keysize -a -z $filename> $tmpfile");
            $req = `cat $tmpfile`;

            # try the flags that work with nethsm
            if ($req eq "") {
                system("certutil -d $instanceDir/alias $hw -f $instanceDir/conf/.pwfile -R --keyAttrFlags \"token,private,sensitive,unextractable\" --keyOpFlagsOff derive -s \"$cert_dn\" -k ec -q $keysize -a -z $filename> $tmpfile");
                $req = `cat $tmpfile`;
            }
            # try the flags that work with lunasa
            if ($req eq "") {
                system("certutil -d $instanceDir/alias $hw -f $instanceDir/conf/.pwfile -R --keyAttrFlags \"private,unextractable\" --keyOpFlagsOff derive -s \"$cert_dn\" -k ec -q $keysize -a -z $filename> $tmpfile");
                $req = `cat $tmpfile`;
            }
            if ($req eq "") {
                &PKI::TPS::Wizard::debug_log("NamePanel: key generation failed on $tokenname.  Please check to see if this is a supported hardware.");
            }
            system("rm $tmpfile");
        } else {
            &PKI::TPS::Wizard::debug_log("NamePanel: update unsupported keytype $keytype");
        }
        system("rm $filename");

        my $save_line = 0;
        my @req_a = split "\n", $req;
        foreach my $line (@req_a) {
            chomp( $line );
            $line =~ s///g;
            if ($line eq $cert_req_header) {
                $save_line = 1;
            } elsif( $line eq $cert_req_footer ) {
                $save_line = 0;
                last;
            } elsif( $save_line == 1 ) {
                $cert_request .= "$line";
            }
        }
        &PKI::TPS::Wizard::debug_log("NamePanel: update putting cert_request in CS.cfg: $cert_request");
        $::config->put("preop.cert.$certtag.certreq", $cert_request);
        $::config->commit();

GEN_CERT:
# =====request for certs========
#   see if there is an existing cert

        my $cert = $::config->get("preop.cert.$certtag.cert");
        my $sdom = $::config->get("config.sdomainEEURL");
        my $sdom_url = new URI::URL($sdom);

        if (($useExternalCA eq "on") && ($certtag ne "subsystem")) {
                &PKI::TPS::Wizard::debug_log("NamePanel: update External CA selected");
            if ($cert eq "") {
                &PKI::TPS::Wizard::debug_log("NamePanel: update no cert found...need manual enrollment");
            }
        } else {
            if ($cert eq "") {
                &PKI::TPS::Wizard::debug_log("NamePanel: update External CA not selected...need automatic enrollment");

                my $machineName = $::config->get("service.machineName");
                my $securePort = $::config->get("service.securePort");
                my $session_id = $::config->get("preop.sessionID");

                if ($cert_request ne "") {
                    &PKI::TPS::Wizard::debug_log("NamePanel: update found existing request: $cert_request");
                } else {
                    &PKI::TPS::Wizard::debug_log("NamePanel: update existing request not found");
                    #something is wrong...no request, no cert
                    goto DONE;
                    return  $cert;
                }

                my $instanceID = $::config->get("service.instanceID");
                my $instanceDir = $::config->get("service.instanceDir");
                my $db_password = "";
                &PKI::TPS::Wizard::debug_log("NamePanel: greping password");
                 
                my $tmpfile = "/tmp/grep$$"; 
                system ("grep \"internal:\" \"$instanceDir/conf/password.conf\" | cut -c10- > $tmpfile");
                $db_password = `cat $tmpfile`;
                $db_password =~ s/\n$//g;
                system("rm $tmpfile");

                my $profile_id = $::config->get("preop.cert.$certtag.profile");
                &PKI::TPS::Wizard::debug_log("NamePanel: profileId=" . $profile_id);
                my $requestor_name = "TPS-" . $machineName . "-" . $securePort;
                my $params = "profileId=" . $profile_id . "&" .
                      "cert_request_type=" . "pkcs10" . "&" .
                      "requestor_name=" . $requestor_name . "&" .
                      "cert_request=" .
                          URI::Escape::uri_escape("$cert_request") . "&" .
                      "xmlOutput=true" . "&" .
                      "sessionID=" . $session_id .  "&" .
                      "auth_hostname=" . $sdom_url->host . "&" .
                      "auth_port=" . $sdom_url->port;

                if ($certtag eq "subsystem") {
                    $host = $sdom_url->host;
                    $https_ee_port = $sdom_url->port;
                }
                if ($changed eq "true") {
                # nickname changed is true, using token passwd for calling sslget
$req = "/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$token_pwd\" -v -n \"$sslnickname\" -r \"/ca/ee/ca/profileSubmit\" $host:$https_ee_port";
$debug_req = "/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"(sensitive)\" -v -n \"$sslnickname\" -r \"/ca/ee/ca/profileSubmit\" $host:$https_ee_port";
                } else {
                # nickname changed is false, using internal passwd for calling sslget
$req = "/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"$db_password\" -v -n \"$sslnickname\" -r \"/ca/ee/ca/profileSubmit\" $host:$https_ee_port";
$debug_req = "/usr/bin/sslget -e \"$params\" -d \"$instanceDir/alias\" -p \"(sensitive)\" -v -n \"$sslnickname\" -r \"/ca/ee/ca/profileSubmit\" $host:$https_ee_port";
                }

                &PKI::TPS::Wizard::debug_log("debug_req = " . $debug_req);
                my $content = `$req`;
                &PKI::TPS::Wizard::debug_log("content = " . $content);

                $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
                $content = $1;

                if ($content eq "") {
                   $::symbol{errorString} = "CA returned no response. Please check that the CA is available and also check the host's firewall settings.";
                   return 0;
                }

                my $parser = XML::Simple->new();
                &PKI::TPS::Wizard::debug_log("NamePanel: response content= " . $content);
                my $response = $parser->XMLin($content);
                my $status = $response->{Status};
                if ($status ne "0") {
                    my $error = $response->{Error};
                    &PKI::TPS::Wizard::debug_log("NamePanel: Error = $error");
                    $::symbol{errorString} = "CA response: $error.  Please check previous related panels." . " Please check that the CA is available and also check the host's firewall settings.";
                    return 0;
                }

                $cert = $response->{Requests}->{Request}->{b64};
                &PKI::TPS::Wizard::debug_log("NamePanel: new cert generated= " . $cert);

#            my $reqid = $response->{Requests}->{Request}->{Id};
#            $::config->put("preop.admincert.requestId.0", $reqid);
#            my $sn = $response->{Requests}->{Request}->{serialno};
#            $::config->put("preop.admincert.serialno.0", $sn);
#            $::config->commit();

                &PKI::TPS::Wizard::debug_log("NamePanel: update putting cert in CS.cfg: $cert");
                $::config->put("preop.cert.$certtag.cert", $cert);
                $::config->commit();

            } else {
                # cert is not null
                &PKI::TPS::Wizard::debug_log("NamePanel: update External CA not selected. Cert found...no need for enrollment");
            }

#               write cert to file so certutil can import
            my $cert_fn = "$instanceDir/conf/".$certtag."_cert.txt";
            open FILE, "> $cert_fn";
            print FILE $cert_header."\n".$cert."\n".$cert_footer;
            close FILE;

            # import cert, whether it was imported before or not
            my $nickname = $::config->get("preop.cert.$certtag.nickname");
            if ($nickname eq "") {
        #XXX
                $nickname = "TPS ".$certtag." cert";
                &PKI::TPS::Wizard::debug_log("NamePanel: update nickname not found for $certtag  -- try $nickname");
            }

            if ($certtag ne "sslserver") {
                &PKI::TPS::Wizard::debug_log("NamePanel: update: try to delete existing cert $nickname, if any....ok if it fails");
                $tmp = `certutil -d $instanceDir/alias -D -n "$nickname"`;
                $tmp = `certutil -d $instanceDir/alias -D $hw -f $instanceDir/conf/.pwfile -n "$tk$nickname"`;
            } else {
                &PKI::TPS::Wizard::debug_log("NamePanel: update: try to delete existing cert $sslnickname, if any....ok if it fails");
                $tmp = `certutil -d $instanceDir/alias -D -n "$sslnickname"`;
                $tmp = `certutil -d $instanceDir/alias -D $hw -f $instanceDir/conf/.pwfile -n "$tk$sslnickname"`;
            }

            &PKI::TPS::Wizard::debug_log("NamePanel: update: try to import cert from $cert_fn");
            if ($certtag ne "audit_signing") {
                $tmp = `certutil -d $instanceDir/alias $hw -f $instanceDir/conf/.pwfile -A -n "$nickname" -t "u,u,u" -a -i $cert_fn`;
            } else {
               $tmp = `certutil -d $instanceDir/alias $hw -f $instanceDir/conf/.pwfile -A -n "$nickname" -t "u,u,Pu" -a -i $cert_fn`;
            }

            # changed the cert, need to change nickname too, if necessary
            if ($hw ne "") {
                if ($certtag eq "sslserver") {
                    if ($changed eq "false") {
                        $::config->put("preop.cert.$certtag.nickname", "$tk$nickname");
                    }
                    $changed = "true";
                } elsif ($certtag eq "subsystem") {
                    &PKI::TPS::Wizard::debug_log("NamePanel: update: sslnickname changed");
                    $::config->put("preop.cert.$certtag.nickname", "$tk$nickname");
                    $::config->put("conn.ca1.clientNickname", "$tk$nickname");
                    $::config->put("conn.drm1.clientNickname", "$tk$nickname");
                    $::config->put("conn.tks1.clientNickname", "$tk$nickname");
                } else {
                    &PKI::TPS::Wizard::debug_log("NamePanel: update: $certtag changed");
                    $::config->put("preop.cert.$certtag.nickname", "$tk$nickname");
                }
                $::config->commit();
             } else {
                if ($certtag eq "subsystem") {
                    # setting these just in case the subsystem nickname changed.
                    &PKI::TPS::Wizard::debug_log("NamePanel: update: setting in case the subsystem nickname changed");
                    $::config->put("conn.ca1.clientNickname", "$nickname");
                    $::config->put("conn.drm1.clientNickname", "$nickname");
                    $::config->put("conn.tks1.clientNickname", "$nickname");
                }
                $::config->commit();
             }
      

            &PKI::TPS::Wizard::debug_log("NamePanel: update: done importing cert: $tk$nickname");
            $tmp = `rm $cert_fn`;
        }
    }

    # set selftest and audit logging variables (always use the "latest" subsystem nickname)
    my $selftestNickname = $::config->get( "preop.cert.subsystem.nickname" );
    my $selftestNickname_sslserver = $::config->get( "preop.cert.sslserver.nickname" );
    my $selftestNickname_audit_signing = $::config->get( "preop.cert.audit_signing.nickname" );
    $::config->put( "selftests.plugin.TPSPresence.nickname",
                    "$selftestNickname" );
    $::config->put( "selftests.plugin.TPSValidity.nickname", 
                    "$selftestNickname" );

    $::config->put( "tps.cert.sslserver.nickname",
                    "$selftestNickname_sslserver" );
    $::config->put( "tps.cert.subsystem.nickname",
                    "$selftestNickname" );
    $::config->put( "tps.cert.audit_signing.nickname",
                    "$selftestNickname_audit_signing" );

    $::config->put( "logging.audit.signedAuditCertNickname",
                    "$selftestNickname_audit_signing" );

DONE:
    $::config->put("preop.namepanel.done", "true");
    $::config->commit();

    &PKI::TPS::Wizard::debug_log("NamePanel: removing pwfile");
    my $tmp = `rm $instanceDir/conf/.pwfile`;
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

use Data::Dumper;

sub display
{
    my ($q) = @_;
    &PKI::TPS::Wizard::debug_log("NamePanel: display");

    my $domain_name = $::config->get("preop.securitydomain.name");
    if ($domain_name eq "") {
        $domain_name = "TPS Domain";
    }
    my $machine_name =  $::config->get("service.machineName");
    my $instance_id =  $::config->get("service.instanceID");

    my $i = 0;
    foreach my $certtag (@PKI::TPS::Wizard::certtags) {
        &PKI::TPS::Wizard::debug_log("NamePanel: display certtag=$certtag");
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
                &PKI::TPS::Wizard::debug_log("NamePanel: display other certtag=$certtag");
                $cert_dn = $certtag;
            }
            $::config->put("preop.cert.".$certtag.".dn", $cert_dn);
            $::config->commit();
        } else {
          if (!($cert_dn =~ /O=/)) {
            $cert_dn .= ", O=" . $domain_name;
            $::config->put("preop.cert.".$certtag.".dn", $cert_dn);
            $::config->commit();
          }
        }

        my $name = $::config->get("preop.cert.".$certtag.".userfriendlyname");
        if ($name eq "") {
            $name = $certtag."Cert ".$instance_id;
            $::config->put("preop.cert.".$certtag.".userfriendlyname", $name);
            $::config->commit();
        }

        my $cert = new PKI::TPS::CertInfo($name,
                  $cert_dn, $certtag);
        $::symbol{certs}[$i++] = $cert;
    }

    &PKI::TPS::Wizard::debug_log("NamePanel: getting CA info");
    $::symbol{urls}        = [];
    my $count = 0;

    while (1) {
      my $host = $::config->get("preop.securitydomain.ca$count.host") || "";
      if ($host eq "") {
        goto DONE;
      }
      my $https_ee_port = $::config->get("preop.securitydomain.ca$count.secureport");
      my $name = $::config->get("preop.securitydomain.ca$count.subsystemname");
      my $item = $name . " - https://" . $host . ":" . $https_ee_port;
      $::symbol{urls}[$count++] = $item;

    }
DONE:

    $::symbol{urls}[$count++] = "External CA";
    $::symbol{urls_size}   = $count+1;

    return 1;
}


# arg0 filename containing certificate request
# return certificate request plus header and footer
sub extract_cert_req_from_file
{
    my $save_line = 0;

    my $filename = $_[0];

    my $fd = new FileHandle;

    my $cert_request = "";

    $fd->open( "<$filename" ) or die "Could not open '$filename'!\n";

    while( <$fd> )
    {
        my $line = $_;
        chomp( $line );

        if( $line eq $cert_req_header ) {
            $save_line = 1;
            $cert_request .= "$line\n";
        } elsif( $line eq $cert_req_footer ) {
            $cert_request .= "$line\n";
            $save_line = 0;
            last;
        } elsif( $save_line == 1 ) {
            $cert_request .= "$line\n";
        }
    }

    $fd->close();

    return $cert_request;
}

# arg0 message containing certificate request
# return certificate request sans header and footer
sub extract_cert_req_from_file_sans_header_and_footer
{
    my $filename = $_[0];
    my $save_line = 0;

    my $fd = new FileHandle;

    my $cert_request = "";

    $fd->open( "<$filename" ) or die "Could not open '$filename'!\n";

    while( <$fd> )
    {
        my $line = $_;
        chomp( $line );

        if( $line eq $cert_req_header ) {
            $save_line = 1;
        } elsif( $line eq $cert_req_footer ) {
            $save_line = 0;
            last;
        } elsif( $save_line == 1 ) {
            $cert_request .= "$line\n";
        }
    }

    $fd->close();

    return $cert_request;
}

sub is_panel_done
{
   return $::config->get("preop.namepanel.done");
}

1;
