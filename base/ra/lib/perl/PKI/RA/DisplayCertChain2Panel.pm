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
use FileHandle;

package PKI::RA::DisplayCertChain2Panel;
$PKI::RA::DisplayCertChain2Panel::VERSION = '1.00';

use PKI::RA::BasePanel;
our @ISA = qw(PKI::RA::BasePanel);

our $cert_header="-----BEGIN CERTIFICATE-----";
our $cert_footer="-----END CERTIFICATE-----";

sub new { 
    my $class = shift;
    my $self = {}; 

    $self->{"isSubPanel"} = \&is_sub_panel;
    $self->{"hasSubPanel"} = \&has_sub_panel;
    $self->{"isPanelDone"} = \&PKI::RA::Common::no;
    $self->{"getPanelNo"} = &PKI::RA::Common::r(7);
    $self->{"getName"} = &PKI::RA::Common::r("Display Certificate Chain");
    $self->{"vmfile"} = "displaycertchain2panel.vm";
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

sub readFile
{
    my $fn = $_[0];
    open FILE, "< $fn" or return "";
    my $content =  join "",<FILE>;
    close FILE;

    return $content;
}

sub validate
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DisplayCertChain2Panel: validate");
    return 1;
}

sub update
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DisplayCertChain2Panel: update");

    my $instanceDir = $::config->get("service.instanceDir");

#    my $caCert = readFile("$instanceDir/conf/caCertChain2.txt");
    my $caCert = extract_cert_from_file_sans_header_and_footer("$instanceDir/conf/caCertChain2.txt");

    #store in config
    $::config->put("preop.ca.certchain", $caCert);
    $::config->commit();
    # import it into the security database
    my $tmp = `p7tool -d $instanceDir/alias -p $instanceDir/conf/chain2cert -a -i $instanceDir/conf/caCertChain2.txt -o $instanceDir/conf/CAchain2_pp.txt`;
    my $r =  $? >> 8;
    my $failed = $? & 127;
    if (($r > 0) && ($r < 10) && !$failed)  {
        my $i = 0;
        while ($i ne $r) {
            $tmp = `certutil -d $instanceDir/alias -D -n "Trusted CA c2cert$i"`;
            $tmp = `certutil -d $instanceDir/alias -A -f $instanceDir/conf/.pwfile -n "Trusted CA c2cert$i"  -t "CT,C,C" -i $instanceDir/conf/chain2cert$i.der`;
            $i++
        }
    }

    # clean up
#    my $tmp = `rm $instanceDir/conf/caCertChain2.txt`;
#    $tmp = `rm $instanceDir/conf/CAchain2_pp.txt`;

    return 1;
}

sub display
{
    my ($q) = @_;
    &PKI::RA::Wizard::debug_log("DisplayCertChain2Panel: display");
    my $instanceDir = $::config->get("service.instanceDir");

    my $found = -e "$instanceDir/conf/caCertChain2.txt";
    my $certpp = "";
    if ($found) {
        &PKI::RA::Wizard::debug_log("DisplayCertChain2Panel: display found caCertChain2.txt");
        my $tmp = `p7tool -d $instanceDir/alias -p $instanceDir/conf/chain2cert -a -i $instanceDir/conf/caCertChain2.txt -o $instanceDir/conf/CAchain2_pp.txt`;

        $certpp = readFile("$instanceDir/conf/CAchain2_pp.txt");
        &PKI::RA::Wizard::debug_log("DisplayCertChain2Panel: display read CAchain2_pp.txt");
        $certpp =~ s/"//g;
        &PKI::RA::Wizard::debug_log("DisplayCertChain2Panel: certpp2= $certpp");
    }

#      $symbol{certchain}        = [ "cert1", "cert2" ];
#      $symbol{certchain_size}   = 2;
    $::symbol{certchain}        = "$certpp";
    $::symbol{certchain_size}   = 1;

    &PKI::RA::Wizard::debug_log("DisplayCertChain2Panel: display done");
    return 1;
}

# return certificate sans header and footer
# -- all in a one-liner
sub extract_cert_from_file_sans_header_and_footer
{
    my $filename = $_[0];
    my $save_line = 0;

    my $fd = new FileHandle;

    my $cert = "";

    $fd->open( "<$filename" ) or die "Could not open '$filename'!\n";

    while( <$fd> )
    {
        my $line = $_;
        chomp( $line );
        $line =~ s/^M//g;

        if( $line eq $cert_header ) {
            $save_line = 1;
        } elsif( $line eq $cert_footer ) {
            $save_line = 0;
            last;
        } elsif( $save_line == 1 ) {
            $cert .= "$line";
        }
    }

    $fd->close();

    return $cert;
}

1;
