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

#######################################
# This plugins mails a notification
# to an email specified in the request.
#######################################
package PKI::Request::Plugin::EmailNotification;

use DBI;
use PKI::Base::TimeTool;

#######################################
# Instantiate this plugin
#######################################
sub new {
  my $self = {};
  bless ($self);
  return $self;
}

sub substitute {
  my ($self, $cfg, $queue, $prefix, $req, $line) = @_;

  my $mail_to = $cfg->get($prefix . ".mailTo");

  # if mail_to starts with $, retrieve value from request
  if ($mail_to =~ /^\$/) { 
    $mail_to =~ s/\$//g;
    $mail_to = $req->{$mail_to};
  }
  my $machineName = $cfg->get("service.machineName");
  my $securePort = $cfg->get("service.securePort");
  my $unsecurePort = $cfg->get("service.unsecurePort");
  my $subject_dn = $req->{'subject_dn'};

  $line =~ s/\$mail_to/$mail_to/g;
  $line =~ s/\$request_id/$req->{'rowid'}/g;
  $line =~ s/\$machineName/$machineName/g;
  $line =~ s/\$securePort/$securePort/g;
  $line =~ s/\$unsecurePort/$unsecurePort/g;
  $line =~ s/\$subject_dn/$subject_dn/g;
  return $line;
}

#######################################
# Processes plugin
#######################################
sub process {
  my ($self, $cfg, $queue, $prefix, $req) = @_;
  my $queue = PKI::Request::Queue->new();
  $queue->open($cfg);
  my $ref = $queue->read_request($req->{rowid});

  my $req_err = $ref->{errorString};
  if ($req_err ne "0") {
    return;
  }

  my $mail_to = $cfg->get($prefix . ".mailTo");
  if ($mail_to eq "") {
    return;
  }

  my $template_dir = $cfg->get($prefix . ".templateDir");
  my $template_file = $cfg->get($prefix . ".templateFile");

  open(SENDMAIL, "|/usr/sbin/sendmail -t");
  open(F,"$template_dir/$template_file");
  while (<F>) {
    print SENDMAIL $self->substitute($cfg, $queue, $prefix, $ref, $_);
  }
  close(F);
  close(SENDMAIL);
}

1;
