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
