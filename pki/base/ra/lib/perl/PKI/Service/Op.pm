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

package PKI::Service::Op;

use PKI::Base::UserStore;
use PKI::Base::CertStore;

sub new {
  my $self = {};
  bless ($self);
  return $self;
}

sub debug_log()
{
  my ($self, $cfg, $msg) = @_;

  my $date = `date`;
  chomp($date);
  open(DEBUG, ">>" . $cfg->get("logging.debug.filename"));
  print DEBUG "$date - $msg\n";
  close(DEBUG);
}

sub debug_params()
{
  my ($self, $cfg, $q) = @_;

  my $date = `date`;
  chomp($date);
  $self->debug_log($cfg, "$date - URL '" . $ENV{REQUEST_URI} . "'");
  my @names = $q->param();
  foreach my $k (@names) {
    $self->debug_log($cfg, "$date - Param $k='" . $q->param($k) . "'");
  }
}

sub get_client_certificate()
{
  my ($self) = @_;

  my $user_cert = $ENV{"SSL_CLIENT_CERT"};
  $user_cert =~ s/-----BEGIN CERTIFICATE-----//g;
  $user_cert =~ s/-----END CERTIFICATE-----//g;
  $user_cert =~ s/\n//g;

  return $user_cert;
}

sub get_current_uid()
{
  my ($self, $cfg) = @_;

  my $user_cert = $self->get_client_certificate();

  my $us = PKI::Base::UserStore->new();
  $us->open($cfg);
  my $ref = $us->map_user($user_cert);
  if (!defined($ref)) {
    return "";
  }
  $us->close();

  return $ref->{'uid'};
}

sub get_csr_by_cert()
{
  my ($self, $cfg) = @_;

  my $user_cert = $self->get_client_certificate();
  my $cs = PKI::Base::CertStore->new();
  $cs->open($cfg);
  my $ref = $cs->map_certificate($user_cert);
  if (!defined($ref)) {
    return "";
  }
  $us->close();

  return $ref->{'csr'};
}

sub get_cert_record()
{
  my ($self, $cfg) = @_;

$self->debug_log( $cfg, "in get_cert_record");
  my $user_cert = $self->get_client_certificate();
  my $cs = PKI::Base::CertStore->new();
  $cs->open($cfg);
  my $ref = $cs->map_certificate($user_cert);
  if (!defined($ref)) {
$self->debug_log( $cfg, "in get_cert_record: map_certificate ref none");
    return "";
  }
$self->debug_log( $cfg, "in get_cert_record: got map_certificate ref");
  $cs->close();

  return $ref;
}

sub get_current_roles()
{
  my ($self, $cfg) = @_;

  my $uid = $self->get_current_uid($cfg);
  my $us = PKI::Base::UserStore->new();
  $us->open($cfg);
  my @roles = $us->get_roles($uid);
  $us->close();

  return @roles;
}

sub get_roles_of()
{
  my ($self, $cfg, $uid) = @_;

  my $us = PKI::Base::UserStore->new();
  $us->open($cfg);
  my @roles = $us->get_roles($uid);
  $us->close();

  return @roles;
}

sub admin_auth()
{
  my ($self, $cfg) = @_;

  my $user_cert = $self->get_client_certificate();

  # authentication
  my $us = PKI::Base::UserStore->new();
  $us->open($cfg);
  my $ref = $us->map_user($user_cert);
  if (!defined($ref)) {
    return 0;
  }
  my @roles = $us->get_roles($ref->{'uid'});
  $us->close();

  # authorization
  my $authorized_groups = $cfg->get("admin.authorized_groups");
  $self->debug_log( $cfg, "in admin_auth: authorized groups are: $authorized_groups");
  my @authorizedGroups = split(/,/, $authorized_groups);
  my $authorized = 0;
  foreach my $role (@roles) {
     $self->debug_log( $cfg, "in admin_auth: user has group $role");
    if (grep /^$role$/, @authorizedGroups) {
      $self->debug_log( $cfg, "in admin_auth: group matched");
      $authorized = 1;
    }
  }
  if (!$authorized) {
    $self->debug_log( $cfg, "in admin_auth: no group matched");
    return 0;
  }
  return 1;
}

sub agent_auth()
{
  my ($self, $cfg) = @_;

  my $user_cert = $self->get_client_certificate();

  # authentication
  my $us = PKI::Base::UserStore->new();
  $us->open($cfg);
  my $ref = $us->map_user($user_cert);
  if (!defined($ref)) {
    return 0;
  }
  my @roles = $us->get_roles($ref->{'uid'});
  my $j = join(",", @roles);
  $self->debug_log( $cfg, "in agent_auth: $ref->{'uid'} has roles: $j");
  $us->close();

  # authorization
  my $authorized_groups = $cfg->get("agent.authorized_groups");
  $self->debug_log( $cfg, "in agent_auth: authorized groups are: $authorized_groups");
  my @authorizedGroups = split(/,/, $authorized_groups);
  my $authorized = 0;
  foreach $role (@roles) {
    if (grep /^$role$/, @authorizedGroups) {
      $self->debug_log( $cfg, "in agent_auth: group matched");
      $authorized = 1;
    }
  }
  if (!$authorized) {
    $self->debug_log( $cfg, "in agent_auth: no group matched");
    return 0;
  }
  return 1;
}

sub process {
  my ($self) = @_;
}

sub escape_xml
{
  my ($v) = @_;
  $v =~ s/\"/&quot;/g;
  $v =~ s/\'/&apos;/g;
  $v =~ s/\&/&amp;/g;
  $v =~ s/</&lt;/g;
  $v =~ s/>/&gt;/g;
  return $v;
}

sub get_xml
{
    my ($s, $v) = @_;

    my $result;
    if (ref($v) eq "HASH") {
      foreach my $xkey (keys %$v) {
              $result .= "<" . $xkey . ">";
              $result .= &get_xml($xkey, $v{$xkey});
          #    $result .= "-" . ref($xkey);
              $result .= "</" . $xkey . ">";
            }
    } elsif (ref($v) eq "PKI::RA::GlobalVar") {
      foreach my $xkey (keys %$v) {
              $result .= "<" . $xkey . ">";
              $result .= &get_xml($xkey, $$v{$xkey}->());
          #    $result .= "-" . ref($xkey);
              $result .= "</" . $xkey . ">";
            }
    } elsif (ref($v) eq "ARRAY") {
            my $pos = 0;
            foreach my $item (@$v) {
              $result .= "<element>";
              $result .= &get_xml("p" . $pos, $item);
          #    $result .= "-" . ref($item);
              $result .= "</element>";
              $pos++;
            }
    } else {
            $result .= &escape_xml($v);
    }
  return $result;
}

sub xml_output {
  my ($self, $c) = @_;

  my $result = "<xml>";
  foreach $s (sort keys %$c) {
    if ($s =~ /^__/) {
      next;
    }
    $result .= "<" . $s . ">";
    my $v = $$c{$s};
    $result .= &get_xml($s, $v);
    $result .= "</" . $s . ">";
  }
  $result .= "</xml>";
  return "$result\n";
}

sub execute {
  my ($self) = @_;
  $self->process();
}

1;
