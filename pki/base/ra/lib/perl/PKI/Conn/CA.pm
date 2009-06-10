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
package PKI::Conn::CA;

use URI::URL;
use URI::Escape;
use XML::Simple;
use Data::Dumper;
use DBI;
use PKI::Base::TimeTool;
use PKI::Base::CertStore;
use PKI::Base::Util;
use PKI::Request::Queue;

#######################################
# Constructs a request queue
#######################################
sub new {
  my $self = {};
  bless ($self);
  return $self;
}

#######################################
# Opens request queue
#######################################
sub open {
  my ($self, $cfg) = @_;
  $self->{cfg} = $cfg;
  my $certstore = PKI::Base::CertStore->new();
  $certstore->open($cfg);
  $self->{certstore} = $certstore;
}

#######################################
# Enrolls
#######################################
sub enroll {
  my ($self, $rid, $con_id, $profile_id, $cert_request_type, $cert_request) = @_;

  my $cfg = $self->{cfg};
  my $instdir = $cfg->get("service.instanceDir");
  my $db_password = `grep \"internal:\" \"$instdir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

  my $nickname = $cfg->get("conn." . $con_id . ".clientNickname");
  my $cahostport = $cfg->get("conn." . $con_id . ".hostport");
  my ($host, $port) = split(/:/, $cahostport);

  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);
  my $req = $queue->read_request($rid);
  if ($req->{'subject_dn'} ne "unavailable") {
    $subject = $req->{'subject_dn'};
  }

  my $tmpfile = "/tmp/tmp-$rid-$$";
  my $params = "profileId=" . $profile_id . "&" .
                  "requestor_name=" . 
                      URI::Escape::uri_escape("$requestor_name") . "&" .
                  "cert_request_type=" . $cert_request_type . "&" .
                  "subject=" . 
                      URI::Escape::uri_escape("$subject") . "&" .
                  "cert_request=" .
                      URI::Escape::uri_escape("$cert_request") . "&" .
                  "xmlOutput=true";
  system("/usr/bin/sslget -e \"$params\" -d \"$instdir/alias\" -p \"$db_password\" -v -n \"$nickname\" -r \"/ca/ee/ca/profileSubmit\" $host:$port > $tmpfile");

  my $content = `cat $tmpfile`;
  if ($content eq "") {
    $queue->set_request($rid, "errorString", "CA Connection Error");
    $queue->set_request($rid, "status", "ERROR");
    $queue->close();

    $queue->close();
    return "";
  }

  $content =~ /(\<XMLResponse\>.*\<\/XMLResponse\>)/;
  $content = $1;

  my $xmlparser = XML::Simple->new();
  my $response = $xmlparser->XMLin($content);

  my $status = $response->{Status};
  if ($status ne "0") {
    my $errorString = $response->{Error};

    $queue->set_request($rid, "errorString", "CA: ".$errorString);
    $queue->set_request($rid, "status", "ERROR");

    $queue->close();
    return "";
  }

  #reset to 0 in case of re-approval
  $queue->set_request($rid, "errorString", "0");
  my $req = $queue->read_request($rid);
  my $approved_by = $req->{'processed_by'};
  my $serialno = $response->{Requests}->{Request}->{serialno};
  $queue->set_request($rid, "serialno", $serialno);
  my $subject_dn = $response->{Requests}->{Request}->{SubjectDN};
  $queue->set_request($rid, "subject_dn", $subject_dn);
  my $cert = $response->{Requests}->{Request}->{b64};
  $queue->close();
 
  my $util = PKI::Base::Util->new();
  my $csr = $cert_request;
  $csr = $util->normalize_csr($csr);

  $self->{certstore}->add_certificate($serialno, $csr, $subject_dn, $cert, $rid, $approved_by);

  system("rm $tmpfile");

  return $cert;
}

sub get_http_content
{
  my ($self, $filename) = @_;
  my $data = "";
  my $count = `grep Content-Length $filename | cut -d' ' -f2`;
  chomp($count);
  my $file_size = -s $filename;
  my $offset = $file_size - $count;

  open(FP, "<$filename");
  binmode(FP);
  seek(FP, $offset-1, 0);
  read(FP, $data, $count);
  close(FP);
  return $data;
}

#######################################
# Revoke
#######################################
sub revoke {
  my ($self, $rid, $con_id, $serialno, $reason) = @_;

  my $cfg = $self->{cfg};
  my $instdir = $cfg->get("service.instanceDir");
  my $db_password = `grep \"internal:\" \"$instdir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

  my $nickname = $cfg->get("conn." . $con_id . ".clientNickname");
  my $cahostport = $cfg->get("conn." . $con_id . ".hostagentport");

  my $tmpfile = "/tmp/tmp-revoke-$serialno-$$";
  my ($host, $port) = split(/:/, $cahostport);
  my $params = "op=" . "revoke" . "&" .
                  "revocationReason=" .$reason . "&" .
                  "revokeAll=(certRecordId=" ."0x".$serialno . ")&" .
                  "totalRecordCount=" ."1" . "&" .
                  "xml=true";
  system("/usr/bin/sslget -e \"$params\" -d \"$instdir/alias\" -p \"$db_password\" -v -n \"$nickname\" -r \"/ca/agent/ca/doRevoke\" $host:$port > $tmpfile");

  my $content = `cat $tmpfile`;
  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);
  if ($content eq "") {
    $queue->set_request($rid, "errorString", "CA Connection Error");
#    $queue->set_request($rid, "status", "ERROR");
    $queue->close();

    $queue->close();
    return "";
  }
  $content =~ s/\000//;
  $content =~ /(\<xml\>.*\<\/xml\>)/s;
  $content = $1;

  my $req = $queue->read_request($rid);

  my $xmlparser = XML::Simple->new(NormalizeSpace => 2);
  my $response = $xmlparser->XMLin($content);

  my $errorString = $response->{fixed}->{errorDetails};
  my $revoked = $response->{header}->{revoked};

  if ($revoked ne "yes") {
    $queue->set_request($rid, "errorString", "CA:".$errorString);
  } else {
    $queue->set_request($rid, "errorString", "0");
  }
  system("rm $tmpfile");

  $queue->close();
  return;
}

#######################################
# Get Certificate Status
#######################################
sub getCertStatus {
  my ($self, $con_id, $serialno) = @_;

  my $cfg = $self->{cfg};
  my $instdir = $cfg->get("service.instanceDir");
  my $db_password = `grep \"internal:\" \"$instdir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

  my $nickname = $cfg->get("conn." . $con_id . ".clientNickname");
  my $cahostport = $cfg->get("conn." . $con_id . ".hostport");
  my ($host, $port) = split(/:/, $cahostport);

  my $tmpfile = "/tmp/tmp-$serialno-$$";
  my $params = "serialNumber=" . "0x".$serialno . "&" .
                  "xml=true";
  system("/usr/bin/sslget -e \"$params\" -d \"$instdir/alias\" -p \"$db_password\" -v -n \"$nickname\" -r \"/ca/ee/ca/displayBySerial\" $host:$port > $tmpfile");

  my $content = `cat $tmpfile`;
  system("rm $tmpfile");
  if ($content eq "") {
    return "CA: Connection Error";
    system("rm $tmpfile");
  }

  $content =~ /(\<xml\>.*\<\/xml\>)/s;
  $content = $1;

  my $xmlparser = XML::Simple->new(NormalizeSpace => 2);
  my $response = $xmlparser->XMLin($content);

  my $errorString = $response->{fixed}->{errorDetails};
  my $revokeReason = $response->{header}->{revocationReason};

  if ($revokeReason eq "") {
    if ($errorString eq "") {
      return "not revoked";
    } else {
      return "CA:".$errorString;
    }
  } else {
    return "revoked:".$revokeReason;
  }
}

#######################################
# SCEP
#######################################
sub scep_get_ca_cert {
  my ($self, $con_id, $operation, $message) = @_;

  my $cfg = $self->{cfg};
  my $instdir = $cfg->get("service.instanceDir");
  my $db_password = `grep \"internal:\" \"$instdir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

  my $nickname = $cfg->get("conn." . $con_id . ".clientNickname");
  my $cahostport = $cfg->get("conn." . $con_id . ".hostport");
  my ($host, $port) = split(/:/, $cahostport);

  my $tmpfile = "/tmp/tmp-$$";
  my $params = "operation=" . $operation . "&" .
                  "message=" . $message;
  system("/usr/bin/sslget -e \"$params\" -d \"$instdir/alias\" -p \"$db_password\" -n \"$nickname\" -r \"/ca/ee/ca/pkiclient\" $host:$port > $tmpfile");


  my $content = $self->get_http_content($tmpfile);

  system("rm $tmpfile");

  return $content;
}

# decode PKI Message
sub scep_decode {
  my ($self, $con_id, $operation, $message) = @_;

  my $cfg = $self->{cfg};
  my $instdir = $cfg->get("service.instanceDir");
  my $db_password = `grep \"internal:\" \"$instdir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

  my $nickname = $cfg->get("conn." . $con_id . ".clientNickname");
  my $cahostport = $cfg->get("conn." . $con_id . ".hostport");
  my ($host, $port) = split(/:/, $cahostport);

  my $tmpfile = "/tmp/tmp-$$";
  my $params = "operation=" . $operation . "&" .
                  "message=" . $message . "&" .
                  "decode=true";
  system("/usr/bin/sslget -e \"$params\" -d \"$instdir/alias\" -p \"$db_password\" -n \"$nickname\" -r \"/ca/ee/ca/pkiclient\" $host:$port > $tmpfile");


  my $content = $self->get_http_content($tmpfile);

  system("rm $tmpfile");

  return $content;
}

sub scep_pki_message {
  my ($self, $con_id, $operation, $message) = @_;

  my $cfg = $self->{cfg};
  my $instdir = $cfg->get("service.instanceDir");
  my $db_password = `grep \"internal:\" \"$instdir/conf/password.conf\" | cut -c10-`;
    $db_password =~ s/\n$//g;

  my $nickname = $cfg->get("conn." . $con_id . ".clientNickname");
  my $cahostport = $cfg->get("conn." . $con_id . ".hostport");
  my ($host, $port) = split(/:/, $cahostport);

  my $tmpfile = "/tmp/tmp-$$";
  my $params = "operation=" . $operation . "&" .
                  "message=" . $message;
  system("/usr/bin/sslget -e \"$params\" -d \"$instdir/alias\" -p \"$db_password\" -n \"$nickname\" -r \"/ca/ee/ca/pkiclient\" $host:$port > $tmpfile");


  my $content = $self->get_http_content($tmpfile);

  system("rm $tmpfile");

  return $content;
}


#######################################
# Closes connection
#######################################
sub close {
  my ($self) = @_;
  $self->{certstore}->close();
}

1;
