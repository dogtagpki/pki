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

package op;

use lib $ENV{DOCUMENT_ROOT} . "/../lib/perl";

use CGI;
use PKI::Base::Conf;
use PKI::Request::Queue;
use Template::Velocity;
use PKI::Service::Op;
use PKI::Base::Util;
use PKI::Base::Registry;

use vars qw (@ISA);
@ISA = qw(PKI::Service::Op);

sub new {
  my $self = {};
  bless ($self);
  return $self;
}

sub process()
{
  my $self = shift;
  my $q = CGI->new();

  my $docroot = PKI::Base::Registry->get_docroot();
  my $parser = PKI::Base::Registry->get_parser();
  my $cfg = PKI::Base::Registry->get_config();

  my $util = PKI::Base::Util->new();
  my $error = "";

  my $host = $cfg->get("service.machineName");
  my $port = $cfg->get("service.non_clientauth_securePort");

  $self->debug_params($cfg, $q);

  my $cert = $self->get_cert_record($cfg);
  $self->debug_log( $cfg, "after get_cert_record");
  if (!defined($cert) || ($cert eq "")) {
    $self->debug_log( $cfg, "cert not defined");
    $error = "certificate not found in database";
    print $q->redirect("/ee/error.cgi?error=$error");
    return;
  }
  $self->debug_log( $cfg, "got cert");

  my $csr = $cert->{'csr'};
  if ($csr eq "") {
    $error = "csr not found in database";
    print $q->redirect("/ee/error.cgi?error=$error");
    return;
  }
  $self->debug_log( $cfg, "got csr");
  
  my $req_id = $cert->{'rid'};
  if ($req_id eq "") {
    $error = "reqid not found in database";
    print $q->redirect("/ee/error.cgi?error=$error");
    return;
  }
  $self->debug_log( $cfg, "got req_id = $req_id");
  $self->debug_log( $cfg, "before renewl read/create request"); 
  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);
  my $o_req = $queue->read_request($req_id);
  if ($o_req eq "") {
    $self->debug_log( $cfg, "got null o_req");
    print $q->redirect("/ee/error.cgi?error=$error");
    return;
  }

  my $uid = "";
  my $site_id = "";
  my $org_csr = "";
  my $csr_type = "";

  my $data = $o_req->{'data'};
  foreach $nv (split(/;/, $data)) {
    my ($n, $v) = split(/=/, $nv);
    if ($n eq "uid") {
      $uid = $v;
    }
    if ($n eq "site_id") {
      $site_id = $v;
    }
    if ($n eq "csr") {
      $org_csr = $v;
    }
    if ($n eq "csr_type") {
      $csr_type = $v;
    }
  }

  my $new_request = $queue->create_request("renewal",
                     "uid=" . $uid . ";" .
                            "site_id=" . $site_id . ";" .
                            "csr_type=" . $csr_type . ";" .
                            "csr=" . $csr,
                            "orig_reqid=" . $o_req->{'rowid'},
                            $o_req->{'created_by'});

  #self-renewal is created and processed by the same user
  $ref = $queue->approve_request($new_request,  $o_req->{'created_by'});
  my $nreq = $queue->read_request($new_request);
  $error = $nreq->{'errorString'};
  if ($error ne "0") {
    $self->debug_log( $cfg, "after approve request, got error=$error"); 
    print $q->redirect("/ee/error.cgi?error=$error");
    return;
  }

  my %context;
  $context{request_id} = $util->html_encode($new_request);
  $self->debug_log($cfg, "request $new_request created");
  $queue->close();
  $self->debug_log( $cfg, "after renewl read/create request $new_request"); 

  $context{data} = $util->breakline($util->html_encode($ref->{'data'}), 40);
  $context{output} = $util->breakline($util->html_encode($ref->{'output'}), 40);
  $context{serialno} = $util->html_encode($ref->{'serialno'});
  $context{host} = $util->html_encode($host);
  $context{port} = $util->html_encode($port);

  #print $q->redirect("/ee/request/getcert.cgi?id=$new_request");
  my $result = $parser->execute_file_with_context("ee/user/renew.vm",
                     \%context);

  my $xml = $q->param('xml');
  if ($xml eq "true") {
    print "Content-Type: text/xml\n\n";
    print $self->xml_output(\%context);
  } else {
    print "Content-Type: text/html\n\n";
    print "$result";
  }
}

my $op = op->new();
$op->execute();
