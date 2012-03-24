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

package PKI::RA::Modutil;


sub new {
	my $class = shift;
	my ($dir) = @_;

	if (! $dir) { die "no module directory provided\n"; }

	my $self = {};

	$self->{dir} = $dir;
	$self->{modules} = makemodules($self);

	bless $self, $class;
	return $self;
}

sub exists {
	my $self = shift;
	
	return -e "$self->{dir}/secmod.db";
}

sub create {
	my $self = shift;
	
	my $mods = `modutil -force -dbdir '$self->{dir}' -nocertdb -create`;
	return $mods;
}

use Data::Dumper;

sub makemodules {
	my $self = shift;
	my $modules = {};

	my $mods = `modutil -force -dbdir '$self->{dir}' -nocertdb -list`;
 	#my $mods = join "",<::DATA>;

	#print "raw mods = $mods";

	my (@modules) = (
			$mods =~ /
				^       #beginning of a line
				\s+     #some spaces
				\d+\.\s*   #some digits
				(.*?)   #lots of text
				((?=^\s*\d+)|(?=------)) #if we would next match some spaces and digits
					/msxg );

	@modules = grep /.+/ms, @modules;
	
	foreach $module (@modules) {
		#print "Module #$i:$module --\n";
 		$module = "modulename:$module";
		my ($moduleheader, $rest) = (
			$module =~ /
				(.*status: .*?\n)    # moduleheader
				(\s*slot:.*)		 # slot
				(?=\n(\n|$))              #empty line
			  /msxg );
		#print "moduleheader: $moduleheader\n";
		my $m = makehash($moduleheader);
		$modules->{$m->{modulename}} = $m;
		$m->{tokens} = {};

		my @tokens = split "\n\n", $rest;



# get summary slot info with:  -list
		foreach my $token (@tokens) {
			#print "slottext:       $slot\n";
			my $slh = makehash($token);
			$m->{tokens}->{$slh->{token}} = $slh;
		}

# get detailed slot info with:  -list "modulename"

		my $moduledetail = `modutil -force -dbdir '$self->{dir}' -nocertdb -list "$m->{modulename}" 2> /dev/null`;
		my @details= split "\n\n", $moduledetail;
		while ($details[0] !~ /.*Name:.*/)  {
			shift @details;
		};
		$m->{detail} = makehash(shift @details);
		foreach $d (@details) {
			my $sdh = makehash($d);
			my $tokenname = $sdh->{"Token Name"};
			$tokenname =~ s/\s+$//;  # remove trailing spaces
			if ($tokenname) {
				$m->{tokens}->{$tokenname}->{detail} = $sdh;
			}
		}
		$i++;
			
	}
	return $modules;
}

# input: a multi-list string with nv/pairs
# return a hashtable reference 
sub makehash {
	my $str = shift;
	my $ht = { };
	my @lines  = split "\n", $str;
	my $line;
LINE:
	foreach $line (@lines) {
		if ($line =~ /Using database directory/) { next LINE; }
		if ($line =~ /--------------/) { next LINE; }
		my ($name, $value) = ($line =~ /^\s*(.*?):\s*(.*?)\s*$/);
		if ($name) {
			#print "name:$name\n";
			#print "value:$value\n";
			$ht->{$name} = $value;
		}
	}
	return $ht;
}

sub getmodules {
	my $self = shift;
	#print "modules: ".$self->{modules}. "\n";
	#print "keys: ".(join ",",keys %{$self->{modules}})."\n";
	return keys %{$self->{modules}};
}

sub getmodule {
	my $self = shift;
	my $modulename = shift;

	#print Dumper($self->{modules});
	return $self->{modules}->{$modulename};
}


sub gettokens {
	my $self = shift;
	my $module = shift;

	return keys %{$module->{tokens}};
}

sub gettoken {
	my $self = shift;
	my $token= shift;
	foreach my $m (values %{$self->{modules}}) {
		foreach $t (values %{$m->{tokens}}) {
			#print join ",", keys %{$t};
			#print Dumper($t->{detail});
			if ($t->{detail}->{"Token Name"} eq $token) { 
				return $t; 
			}
		}
	}
}



package main;

sub ::test {

# initialize
	my $modutil = new PKI::RA::Modutil(".");

#make database if it doesn't exist
	if (! $modutil->exists()) {
		$modutil->create();
	}

#get an array of module names
	my @mods   = $modutil->getmodules();

	print "Found ".@mods." pkcs#11 modules\n";

#for each module...
	foreach my $modname (@mods) {
		my $module = $modutil->getmodule($modname);

		print "Module: $modname\n";
		print "Library: ".$module->{detail}->{"Library file"}."\n";
		print "Other keys: ".(join ",", keys %{$module->{detail}})."\n";

#find all the tokens in a module, e.g. each partition for a lunasa
		foreach my $tokenname ($modutil->gettokens($module)) {
			print "  token: $tokenname\n";
			my $token = $modutil->gettoken($tokenname);
			
#dump out the information we have on the token
			foreach my $key (keys %{$token}) {
				print "  token keys/values: $key: ".$token->{$key}."\n";
			}
			my @detailkeys = (keys %{$token->{detail}}) ;
			print "  token detail keys:". (join ",", @detailkeys)."\n";
			print "  token detail Manufacturer:". $token->{detail}->{Manufacturer}."\n";
			print "\n";
		}
		print "\n";
	}

}

# this is where 'main' starts

if ($ARGV[0] eq "--test") {
        ::test();
}

1;

__DATA__
Listing of PKCS #11 Modules
-----------------------------------------------------------
  1. NSS Internal PKCS #11 Module
         slots: 2 slots attached
        status: loaded

         slot: NSS Internal Cryptographic Services
        token: NSS Generic Crypto Services

         slot: NSS User Private Key and Certificate Services
        token: NSS Certificate DB

  2. lunasa
        library name: /usr/lunasa/lib/libCryptoki2.so
         slots: 2 slots attached
        status: loaded

         slot: LunaNet Slot
        token: lunasa1-ca

         slot: LunaNet Slot
        token: lunasa2-ca
-----------------------------------------------------------


