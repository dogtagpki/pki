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
# Copyright (C) 2007-2010 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#

package pkicommon;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
 $lib_prefix $obj_ext $path_sep $tmp_dir
 $pki_registry_path
 $verbose $dry_run $hostname $default_hardware_platform
 $default_system_binaries $default_lockdir $default_system_libraries $default_system_user_binaries
 $default_system_user_libraries
 $default_java_path $default_pki_java_path $default_x86_64_jni_java_path $default_system_jni_java_path @default_jar_path
 $default_security_libraries $default_certutil_command
 $default_ldapmodify_command $default_modutil_command
 $default_dir_permissions $default_exe_permissions $default_file_permissions
 $default_initscripts_path $default_registry_path
 $ROOTUID $MAX_WELL_KNOWN_PORT $MAX_RESERVED_PORT $MAX_REGISTERED_PORT $MAX_DYNAMIC_PORT
 $FILE_PREFIX $FTP_PREFIX $HTTP_PREFIX $HTTPS_PREFIX $LDAP_PREFIX $LDAPS_PREFIX
 $PKI_USER $PKI_GROUP $PKI_UID $PKI_GID
 $CA $KRA $OCSP $TKS $RA $TPS
 $CA_INITSCRIPT $KRA_INITSCRIPT $OCSP_INITSCRIPT
 $TKS_INITSCRIPT $RA_INITSCRIPT $TPS_INITSCRIPT
 $install_info_basename $cleanup_basename %installation_info
 $semanage $restorecon $SELINUX_PORT_UNDEFINED $SELINUX_PORT_DEFINED $SELINUX_PORT_WRONGLY_DEFINED

 add_install_info remove_install_info get_install_description
 format_install_info get_install_info_description
 parse_install_info parse_old_cleanup read_old_cleanup
 read_install_info read_install_info_from_dir write_install_info_to_dir uninstall
 is_Windows is_Linux is_Fedora is_RHEL is_RHEL4 setup_platform_dependent_parameters
 set_library_path get_library_path fedora_release
 check_for_root_UID user_disallows_shell
 user_exists create_user
 group_exists create_group user_is_a_member_of_group add_user_as_a_member_of_group
 get_UID_from_username
 get_FQDN check_for_valid_url_prefix
 AreConnectorPortsValid IsLocalPortAvailable IsServerReachable
 get_time_stamp generate_random generate_random_string password_quality_checker
 LDAP_add LDAP_modify
 certutil_create_databases certutil_delete_cert certutil_generate_CSR
 certutil_generate_self_signed_cert certutil_import_cert
 certutil_print_cert certutil_list_certs modutil_add_token
 open_logfile get_logfile_path close_logfile
 prompt printFile emit
 is_path_valid is_name_valid entity_type entity_exists
 file_exists is_file_empty create_empty_file create_file copy_file remove_file
 set_permissions set_owner_group set_file_props
 get_directory_files normalize_path
 directory_exists is_directory_empty create_directory copy_directory remove_directory
 set_owner_group_on_directory_contents
 symlink_exists create_symlink remove_symlink set_owner_group_on_symlink
 run_command get_cs_cfg get_registry_initscript_name 
 register_pki_instance_with_chkconfig deregister_pki_instance_with_chkconfig
 find_jar  
 check_selinux_port parse_selinux_ports add_selinux_port add_selinux_file_context
 );


use File::Slurp qw(read_file write_file);

##############################################################
# This file contains shared data and subroutines for
# the "pkicreate" and "pkiremove" Perl scripts.
##############################################################


##############################################################
# Perl Version
##############################################################

my $MINIMUM_PERL_VERSION = "5.006001";

my $perl_version_error_message = "ERROR:  Using Perl version $] ...\n"
                               . "        Must use Perl version "
                               . "$MINIMUM_PERL_VERSION or later to "
                               . "run this script!\n";

die $perl_version_error_message if $] < $MINIMUM_PERL_VERSION;


##############################################################
# Execution Check
##############################################################

# Check to insure that this script's original
# invocation directory has not been deleted!
my $cwd = `/bin/pwd`;
chomp $cwd;
if (!$cwd) {
    emit("Cannot invoke '$0' from non-existent directory!\n", "error");
    exit 255;
}


##############################################################
# Environment Variables
##############################################################

# untaint called subroutines
if (($^O ne 'Windows_NT') && ($^O ne 'MSWin32')) {
    $> = $<;   # set effective user ID to real UID
    $) = $(;   # set effective group ID to real GID
    $ENV{'PATH'} = '/bin:/usr/bin';
    $ENV{'ENV'} = '' if !defined($ENV{'ENV'});
}


##############################################################
# Perl Modules
##############################################################

use Sys::Hostname;
use FileHandle;
use Socket;
use File::Copy;
use File::Basename;
use File::Path qw(make_path remove_tree);

##############################################################
# Global Variables
##############################################################

# Platform-dependent parameters
our $lib_prefix = undef;
our $obj_ext    = undef;
our $path_sep   = undef;
our $tmp_dir    = undef;

# Whether or not to do verbose mode
our $verbose = 0;

# Controls whether actions are executed (dry_run == false)
# or if actions are only reported (dry_run == true).
our $dry_run = 0;

our $hostname = undef;

# selinux structures
our %selinux_ports = ();

##############################################################
# Shared Default Values
##############################################################

our $pki_registry_path             = undef;

our $default_hardware_platform     = undef;
our $default_system_binaries       = undef;
our $default_lockdir               = undef;
our $default_system_libraries      = undef;
our $default_system_user_binaries  = undef;
our $default_system_user_libraries = undef;
our $default_java_path             = undef;
our $default_pki_java_path         = undef;
our $default_x86_64_jni_java_path  = undef;
our $default_system_jni_java_path  = undef;
our @default_jar_path              = undef;
our $default_security_libraries    = undef;
our $default_certutil_command      = undef;
our $default_ldapmodify_command    = undef;
our $default_modutil_command       = undef;
our $default_initscripts_path      = undef;
our $default_registry_path         = undef;
my  $resteasy_path                 = "/usr/share/java/resteasy";
my  $httpcomponents_path           = "/usr/share/java/httpcomponents";

our $default_dir_permissions       = 00770;
our $default_exe_permissions       = 00770;
our $default_file_permissions      = 00660;

our $semanage                     = "/usr/sbin/semanage";
our $restorecon                   = "/sbin/restorecon";
our $SELINUX_PORT_UNDEFINED       = 0;
our $SELINUX_PORT_DEFINED         = 1;
our $SELINUX_PORT_WRONGLY_DEFINED = 2;



# Use a local variable to denote IPv6
my $is_IPv6 = 0;

# Compute "hardware platform" of Operating System
if ($^O eq "linux") {
    $default_registry_path = "/etc/sysconfig";
    $pki_registry_path = "$default_registry_path/pki";
    $default_initscripts_path = "/etc/rc.d/init.d";
    $default_lockdir = "/var/lock/pki";
    $default_hardware_platform = `uname -i`;
    $default_hardware_platform =~ s/\s+$//g;
    chomp($default_hardware_platform);
    if ($default_hardware_platform eq "i386") {
        # 32-bit Linux
        $default_system_binaries       = "/bin";
        $default_system_libraries      = "/lib";
        $default_system_user_binaries  = "/usr/bin";
        $default_system_user_libraries = "/usr/lib";
        $default_java_path             = "/usr/share/java";
        $default_pki_java_path         = "/usr/share/java/pki";
        $default_system_jni_java_path  = "/usr/lib/java";
        @default_jar_path = ($default_pki_java_path, $default_java_path, $default_system_jni_java_path, $resteasy_path, $httpcomponents_path);
    } elsif ($default_hardware_platform eq "x86_64") {
        # 64-bit Linux
        $default_system_binaries       = "/bin";
        $default_system_libraries      = "/lib64";
        $default_system_user_binaries  = "/usr/bin";
        $default_system_user_libraries = "/usr/lib64";
        $default_java_path             = "/usr/share/java";
        $default_pki_java_path         = "/usr/share/java/pki";
        $default_x86_64_jni_java_path  = "/usr/lib64/java";
        $default_system_jni_java_path  = "/usr/lib/java";
        @default_jar_path = ($default_pki_java_path, $default_java_path, $default_x86_64_jni_java_path,
                             $default_system_jni_java_path, $resteasy_path, $httpcomponents_path);
    } else {
        emit("Unsupported '$^O' hardware platform '$default_hardware_platform'!", "error");
        exit 255;
    }

    # Retrieve hostname
    if (defined($ENV{'PKI_HOSTNAME'})) {
        # IPv6: Retrieve hostname from environment variable
        $hostname = $ENV{'PKI_HOSTNAME'};
        $is_IPv6 = 1;
    } else {
        # IPv4: Retrieve hostname using Sys::Hostname
        $hostname = hostname;
    }
} else {
    emit("Unsupported platform '$^O'!\n", "error");
    exit 255;
}


$default_security_libraries = "$default_system_user_libraries/dirsec";

$default_certutil_command   = "$default_system_user_binaries/certutil";
$default_ldapmodify_command = "$default_system_user_binaries/ldapmodify";
$default_modutil_command    = "$default_system_user_binaries/modutil";


##############################################################
# Global Constants
##############################################################

our $ROOTUID = 0;

our $MAX_WELL_KNOWN_PORT = 511;    #      well-known ports =     0 through   511
our $MAX_RESERVED_PORT   = 1023;   #        reserved ports =   512 through  1023
our $MAX_REGISTERED_PORT = 49151;  #      registered ports =  1024 through 49151
our $MAX_DYNAMIC_PORT    = 65535;  # dynamic/private ports = 49152 through 65535

our $FILE_PREFIX         = "file://";
our $FTP_PREFIX          = "ftp://";
our $HTTP_PREFIX         = "http://";
our $HTTPS_PREFIX        = "https://";
our $LDAP_PREFIX         = "ldap://";
our $LDAPS_PREFIX        = "ldaps://";

# Identity values
our $PKI_USER  = "pkiuser";
our $PKI_GROUP = "pkiuser";
our $PKI_UID   = 17;
our $PKI_GID   = 17;

# Subsystem names
our $CA   = "ca";
our $KRA  = "kra";
our $OCSP = "ocsp";
our $TKS  = "tks";
our $RA   = "ra";
our $TPS  = "tps";

# Subsystem init scripts
our $CA_INITSCRIPT   = "pki-cad";
our $KRA_INITSCRIPT  = "pki-krad";
our $OCSP_INITSCRIPT = "pki-ocspd";
our $TKS_INITSCRIPT  = "pki-tksd";
our $RA_INITSCRIPT   = "pki-rad";
our $TPS_INITSCRIPT  = "pki-tpsd";


##############################################################
# Local Variables
##############################################################

# "identity" parameters
my $fqdn = undef;

# "logging" parameters
my $logfd = undef;
my $logfile_path = undef;



##############################################################
# Routines & data structures used to track & 
# manage installation information
##############################################################

# Basename of the installation info file.
our $install_info_basename = "install_info";

# Basename of the old clean up file.
our $cleanup_basename = ".cleanup.dat";

# Global hash table of installation actions
# Each filesystem path which is modified during installation
# is entered into this table as a key. The value associated
# with the key is an anonymous hash table of key/value pairs,
# e.g. the installation metadata associated with the path.
# This table should not be directly modified, rather use
# the utility subroutines which know how to operate on
# on an installation info table. The utility routines can
# operate on any installation table, but default to using
# this single global table.
our %installation_info = ();

# Table to validate an installation type
my %valid_install_types = ('file'    => 1,
                           'symlink' => 1,
                           'dir'     => 1);

# Table to validate a install action
my %valid_install_action = ('create' => 1,
                            'move'   => 1,
                            'remove' => 1); 

# Table to validate an uninstall action
my %valid_uninstall_action = ('remove'   => 1,
                              'preserve' => 1); 

# Capture information about items modified during installation
#
# add_install_info(path, [type='file'], [uninstall_action='remove],
#                        [install_action='create])
#
# path               the path name of the object
# type               what kind of object
#                    (file, symlink, dir)
# uninstall_action - during uninstall what should be done
#                    (remove, preserve)
# install_action     what was done during install
#                    (create, move, remove)
#
# The data structure used to capture the information is a hash
# table whose keys are path names and whose value is a hash
# table of key/value attributes belonging to the path object.
sub add_install_info {
    my ($path, $type, $uninstall_action, $install_action) = @_;
    my ($install_info) = \%installation_info;
    $type             = 'file'   unless defined($type);
    $uninstall_action = 'remove' unless defined($uninstall_action);
    $install_action   = 'create' unless defined($install_action);
    my $info;

    die "invalid install type ($type) for path ($path)"
        if (!exists($valid_install_types{$type}));

    die "invalid uninstall action ($uninstall_action) for path ($path)"
        if (!exists($valid_uninstall_action{$uninstall_action}));

    die "invalid install action ($install_action) for path ($path)"
        if (!exists($valid_install_action{$install_action}));

    if (exists($install_info->{$path})) {
        $info = $install_info->{$path};
    } else {
        $install_info->{$path} = $info = {};
    }

    $info->{'type'}             = $type;
    $info->{'install_action'}   = $install_action;
    $info->{'uninstall_action'} = $uninstall_action;
}

# Removes the install info for the given path.
# Used primarily after an error occurs.
sub remove_install_info {
    my ($path) = @_;
    my ($install_info) = \%installation_info;

    delete $install_info->{$path};
}

# return text description of installed files and directories
sub get_install_description
{
    my ($install_info) = \%installation_info;

    return get_install_info_description($install_info);
}

# Given a hash of installation information format it into text.
# Each path name is in brackets at the beginning of a line
# followed by the path's attributes, which is an indented line of 
# key = value, for each attribute
#
# The formatted text is referred to as a "Installation Manifest".
#
# returns formatted text
#
# Example:
#
# [/etc/pki-ca]
#     install_action = create
#     type = dir
#     uninstall_action = remove
# [/etc/pki-ca/CS.cfg]
#     install_action = create
#     type = file
#     uninstall_action = remove
#
sub format_install_info
{
    my ($install_info) = @_;
    my ($text, @paths, $path, $info, @key_names, $key, $value);

    $text = "";
    @paths = sort(keys %$install_info);
    foreach $path (@paths) {
        $info = $install_info->{$path};
        $text .= sprintf("[%s]\n", $path);
        @key_names = sort(keys %$info);
        foreach $key (@key_names) {
            $value = $info->{$key};
            $text .= sprintf("    %s = %s\n", $key, $value);
        }
    }
    return $text;
}

# Given a hash of installation information format it into
# into friendly description of what was installed.
#
# Brief Example:
#
# Installed Files:
#     /etc/pki-ca/CS.cfg
#     /var/log/pki-ca-install.log
# Installed Directories:
#     /etc/pki-ca
#     /var/log/pki-ca
# Installed Symbolic Links:
#     /var/lib/pki-ca/logs
# Removed Items:
#     /etc/pki-ca/noise
# 
sub get_install_info_description
{
    my ($install_info) = @_;
    my ($text, @paths, @filtered_paths, $path);

    $text = '';
    @paths = sort(keys %$install_info);
    
    @filtered_paths = grep {my ($info) = $install_info->{$_};
                            $info->{'type'} eq 'file' &&
                            $info->{'install_action'} ne 'remove'} @paths;
    if (@filtered_paths) {
        $text .= "Installed Files:\n";
        foreach $path (@filtered_paths) {
            $text .= "    ${path}\n";
        }
    }

    @filtered_paths = grep {my ($info) = $install_info->{$_};
                            $info->{'type'} eq 'dir' &&
                            $info->{'install_action'} ne 'remove'} @paths;
    if (@filtered_paths) {
        $text .= "Installed Directories:\n";
        foreach $path (@filtered_paths) {
            $text .= "    ${path}\n";
        }
    }

    @filtered_paths = grep {my ($info) = $install_info->{$_};
                            $info->{'type'} eq 'symlink' &&
                            $info->{'install_action'} ne 'remove'} @paths;
    if (@filtered_paths) {
        $text .= "Installed Symbolic Links:\n";
        foreach $path (@filtered_paths) {
            $text .= "    ${path}\n";
        }
    }

    @filtered_paths = grep {my ($info) = $install_info->{$_};
                            $info->{'install_action'} eq 'remove'} @paths;
    if (@filtered_paths) {
        $text .= "Removed Items:\n";
        foreach $path (@filtered_paths) {
            $text .= "    ${path}\n";
        }
    }

    return $text;

}

# Given text as formatted by format_install_info() parse it into
# a install info hash table where each key is a path name and whose
# value is a hash table of key/value pairs.
#
# E.g. this routine parses an "Installation Manifest".
#
# Returns pointer to an install info hash table
sub parse_install_info
{
    my ($text) = @_;
    my ($install_info, @lines, $line, $line_num, $path, $info, $key, $value);

    $install_info = {};
    @lines = split(/\n/, $text);
    $line_num = 0;
    $path = undef;
    $info = undef;

    foreach $line (@lines) {
        $line_num++;
        $line =~ s/#.*//;       # nuke comments
        $line =~ s/\s+$//;      # strip trailing whitespace
        next if !$line;         # skip blank lines

        # Look for quoted path at beginning of line
        if ($line =~ /^\s*\[(.+)\]\s*$/) {
            $path = $1;
            $info = {};
            $install_info->{$path} = $info;
            next;
        }

        if (defined($path)) {
            # Look for key = value in section, must be preceded by whitespace
            undef($key);
            if ($line =~ /^\s+(\w+)\s*=\s*(.*)/) {
                # quoted name followed by a colon followed by an action
                $key = $1;
                $value = $2;
                $info->{$key} = $value;
            }
        }
    }
    return $install_info;
}

# Formerly the installation info was written as an ini style
# file, a section for files and a section for directories.
# Everything in the file was meant to be removed upon uninstall.
#
# Returns an install info style hash table (see parse_install_info)
sub parse_old_cleanup
{
    my ($text) = @_;
    my ($install_info, @lines, $line, $section, $info, $path);

    $install_info = {};
    @lines = split(/\n/, $text);

    foreach $line (@lines) {
        $line =~ s/#.*//;       # nuke comments
        $line =~ s/^\s+//;      # strip leading whitespace
        $line =~ s/\s+$//;      # strip trailing whitespace
        next if !$line;         # skip blank lines

        # Look for section markers
        if ($line =~ /^\s*\[\s*(\w+)\s*\]\s*$/) {
            $section = $1;
            next;
        }

        # Must be path name
        $path = $line;
        $info = {};
        $install_info->{$path} = $info;
        $info->{'uninstall_action'} = 'remove';
        if ($section eq 'files') {
            $info->{'type'} = 'file';
        } elsif ($section eq 'directories') {
            $info->{'type'} = 'dir';
        } else {
            die "unknown cleanup section = \"$section\"\n";
        }
    }
    return $install_info;
}

# Get the contents of the old cleanup file
sub read_old_cleanup
{
    my ($path) = @_;
    my ($text);

    $text = read_file($path);
    return parse_old_cleanup($text);
}

# Get the contents of an install info file
sub read_install_info
{
    my ($path) = @_;
    my ($text);

    $text = read_file($path);
    return parse_install_info($text);
}

# Get the contents of installation info from a directory.
# Supports both the new install info format and the older
# cleanup format. First checks for the presence of the newer
# install info format file, if that's absent reads the older
# cleanup format but returns it as the new install info hash table.
sub read_install_info_from_dir
{
    my ($dir) = @_;
    my ($path);

    $path = "${dir}/${install_info_basename}";
    if (-e $path) {
        return read_install_info($path);
    }

    $path = "${dir}/${cleanup_basename}";
    if (-e $path) {
        return read_old_cleanup($path);
    }

    return undef;
}

# Give an install info hash table writes it formated as a
# "Installation Manifest" into specified directory under
# the name $install_info_basename
#
# Returns pathname of manifest if successful, undef otherwise.
sub write_install_info_to_dir
{
    my ($dir, $install_info) = @_;
    my ($path, $formatted);

    if (! defined($dir)) {
        emit("Cannot write installation manifest, directory unspecified", "error");
        return undef;
    }

    if (! defined($install_info_basename)) {
        emit("Cannot write installation manifest, file basename unspecified", "error");
        return undef;
    }

    if (! -e $dir) {
        emit("Cannot write installation manifest, directory ($dir) does not exist", "error");
        return undef;
    }

    if (! -d $dir) {
        emit("Cannot write installation manifest, directory ($dir) is not a directory", "error");
        return undef;
    }

    if (! -w $dir) {
        emit("Cannot write installation manifest, directory ($dir) is not writable", "error");
        return undef;
    }

    $path = "${dir}/${install_info_basename}";
    $formatted = format_install_info($install_info);
    write_file($path, \$formatted);

    return $path;
}

# Given an Installation Manifest (e.g. install_info) remove the items in
# the manifest marked for removal.
#
# 1) Remove all files and symlinks we created.
#
# 2) Attempt to remove all directories we created, even if they are non-empty.
#
sub uninstall
{
    my ($install_info) = @_;
    my ($result, @paths, @filtered_paths, $path, @dirs);

    $result = 1;

    @paths = sort(keys %$install_info);
    
    # Get a list of files marked for removal.
    @filtered_paths = grep {my ($info) = $install_info->{$_};
                            ($info->{'type'} eq 'file' || $info->{'type'} eq 'symlink') &&
                            $info->{'install_action'} ne 'remove' &&
                            $info->{'uninstall_action'} eq 'remove'} @paths;
    # Remove the files
    if (@filtered_paths) {
        foreach $path (@filtered_paths) {
            $result = 0 if !remove_file($path);
        }
    }

    # Get a list of directories marked for removal.
    @filtered_paths = grep {my ($info) = $install_info->{$_};
                            $info->{'type'} eq 'dir' &&
                            $info->{'uninstall_action'} eq 'remove'} @paths;

    # We need to removed directories starting at the deepest level
    # and progressively work upward, otherwise the directory might
    # not be empty. To accomplish this we sort the directory array
    # based on the number of path components.
    
    # Primary sort by number of path components, longest first.
    # When the number of path components is the same the secondary sort
    # is lexical string comparision.
    @dirs = sort {my ($r, @a, @b);
                  @a = split("/", $a);
                  @b = split("/", $b);
                  $r = @b <=> @a;
                  $r == 0 ? $a cmp $b : $r} @filtered_paths;

    foreach $path (@dirs) {
        $result = 0 if !remove_directory($path, 1);
    }

    return $result;
}

##############################################################
# Generic "platform" Subroutines
##############################################################

# no args
# return 1 - true, or
# return 0 - false
sub is_Windows
{
    if (($^O eq "Windows_NT") || ($^O eq "MSWin32")) {
        return 1;
    }

    return 0;
}


# no args
# return 1 - true, or
# return 0 - false
sub is_Linux
{
    if ($^O eq "linux") {
        return 1;
    }

    return 0;
}


# no args
# return 1 - true, or
# return 0 - false
sub is_Fedora
{
    if (is_Linux() && (-e "/etc/fedora-release")) {
        return 1;
    }

    return 0;
}


# no args
# return 1 - true, or
# return 0 - false
sub is_RHEL {
    if ((! is_Fedora()) && (-e "/etc/redhat-release")) {
        return 1;
    }

    return 0;
}


# no args
# return 1 - true, or
# return 0 - false
sub is_RHEL4 {
    if (is_RHEL()) {
        my $releasefd = new FileHandle;
        if ($releasefd->open("< /etc/redhat-release")) {
            while (defined(my $line = <$releasefd>)) {
                if ($line =~ /Nahant/i) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

# no args
# return release_number
# return 0 if not found
sub fedora_release {
    my $releasefd = new FileHandle;
    if ($releasefd->open("< /etc/fedora-release")) {
            while (defined(my $line = <$releasefd>)) {
                if ($line =~ /Fedora release (\d*)/) {
                    return $1;
                }
            }
    }
    return 0;
}


# no args
# no return value
sub setup_platform_dependent_parameters
{
    # Setup path separators, et. al., based upon platform
    if (is_Windows()) {
        $lib_prefix = "";
        $obj_ext    = ".dll";
        $path_sep   = ";";
        $tmp_dir    = "c:\\temp";
    } elsif ($^O eq "hpux") {
        $lib_prefix = "lib";
        $obj_ext    = ".sl";
        $path_sep   = ":";
        $tmp_dir    = "/tmp";
    } else {
        $lib_prefix = "lib";
        $obj_ext    = ".so";
        $path_sep   = ":";
        $tmp_dir    = "/tmp";
    }

    return;
}


# Takes an array reference containing a list of paths.
# Any item in the list which is undefined will be ignored.
# no return value
sub set_library_path
{
    my ($paths) = @_;
    my ($path);

    $path = join($path_sep, grep(defined($_), @$paths));

    if (is_Windows()) {
        $ENV{'PATH'} = $path;
    } elsif ($^O eq "hpux") {
        $ENV{'SHLIB_PATH'} = $path;
    } else {
        $ENV{'LD_LIBRARY_PATH'} = $path;
    }

    return;
}


# no args
# return Library Path Environment variable
sub get_library_path
{
    if (is_Windows()) {
        return $ENV{'PATH'};
    } elsif ($^O eq "hpux") {
        return $ENV{'SHLIB_PATH'};
    } else {
        return $ENV{'LD_LIBRARY_PATH'};
    }
}


##############################################################
# Generic "identity" Subroutines
##############################################################

# no args
# return 1 - success, or
# return 0 - failure
sub check_for_root_UID
{
    my $result = 0;

    # On Linux/UNIX, insure that this script is being run as "root";
    # First check the "Real" UID, and then check the "Effective" UID.
    if (!is_Windows()) {
        if (($< != $ROOTUID) &&
            ($> != $ROOTUID)) {
            emit("This script must be run as root!\n", "error");
            $result = 0;
        } else {
            # Success -- running script as root
            $result = 1;
        }
    } else {
        emit("Root UID makes no sense on Windows machines!\n", "error");
        $result = 0;
    }

    return $result;
}


# return 1 - exists, or
# return 0 - DOES NOT exist
sub user_exists
{
    my ($username) = @_;

    return defined(getpwnam($username));
}


# Return 1 if success, 0 if failure
sub create_user
{
    my ($username, $groupname) = @_;
    my $command;

    emit(sprintf("create_user(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    if (($username eq $PKI_USER) &&
        ($groupname eq $PKI_GROUP)) {
        # Attempt to create $PKI_USER with $PKI_UID
        emit("create_user():  Adding default PKI user '$username' "
            . "(uid=$PKI_UID) to '/etc/passwd'.\n", "debug");
        if ($^O eq "linux") {
            $command = "/usr/sbin/useradd "
                     . "-g $groupname "
                     . "-d /usr/share/pki "
                     . "-s /sbin/nologin "
                     . "-c 'Certificate System' "
                     . "-u $PKI_UID "
                     . "-r "
                     . $username;
        } elsif ($^O eq "solaris") {
            $command = "/usr/sbin/useradd "
                     . "-g $groupname "
                     . "-d /usr/share/pki "
                     . "-s /bin/false "
                     . "-c 'Certificate System' "
                     . "-u $PKI_UID "
                     . $username;
        } else {
            $command = "/usr/sbin/useradd "
                     . "-g $groupname "
                     . "-d /usr/share/pki "
                     . "-s '' "
                     . "-c 'Certificate System' "
                     . "-u $PKI_UID "
                     . $username;
        }
    } else {
        # Attempt to create $username with random UID
        emit("create_user():  Adding default PKI user '$username' "
            . "(uid=random) to '/etc/passwd'.\n", "debug");
        if ($^O eq "linux") {
            $command = "/usr/sbin/useradd "
                     . "-g $groupname "
                     . "-d /usr/share/pki "
                     . "-s /sbin/nologin "
                     . "-c 'Certificate System' "
                     . $username;
        } elsif ($^O eq "solaris") {
            $command = "/usr/sbin/useradd "
                     . "-g $groupname "
                     . "-d /usr/share/pki "
                     . "-s /bin/false "
                     . "-c 'Certificate System' "
                     . $username;
        } else {
            $command = "/usr/sbin/useradd "
                     . "-g $groupname "
                     . "-d /usr/share/pki "
                     . "-s '' "
                     . "-c 'Certificate System' "
                     . $username;
        }
    }

    return 0 if !run_command($command);
    return user_exists($username);
}


# return 1 - exists, or
# return 0 - DOES NOT exist
sub group_exists
{
    my ($groupname) = @_;

    return defined(getgrnam($groupname));
}


# Return 1 if success, 0 if failure
sub create_group
{
    my ($groupname) = @_;
    my $command;

    emit(sprintf("create_group(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    if ($groupname eq $PKI_GROUP) {
        # Attempt to create $PKI_GROUP with $PKI_GID
        emit("Adding default PKI group '$groupname' "
            . "(gid=$PKI_GID) to '/etc/group'.\n", "debug");
        if ($^O eq "linux") {
            $command = "/usr/sbin/groupadd "
                     . "-g $PKI_GID "
                     . "-r "
                     . $groupname;
        } elsif ($^O eq "solaris") {
            $command = "/usr/sbin/groupadd "
                     . "-g $PKI_GID "
                     . $groupname;
        } else {
            $command = "/usr/sbin/groupadd "
                     . "-g $PKI_GID "
                     . $groupname;
        }
    } else {
        # Attempt to create $groupname with random GID
        emit("Adding default PKI group '$groupname' "
            . "(gid=random) to '/etc/group'.\n", "debug");
        if ($^O eq "linux") {
            $command = "/usr/sbin/groupadd "
                     . $groupname;
        } elsif ($^O eq "solaris") {
            $command = "/usr/sbin/groupadd "
                     . $groupname;
        } else {
            $command = "/usr/sbin/groupadd "
                     . $groupname;
        }
    }

    return 0 if !run_command($command);
    return group_exists($groupname);
}


# return 1 - disallows shell, or
# return 0 - allows shell
sub user_disallows_shell
{
    my ($username) = @_;

    my $result = 0;
    my $sans_shell = "";

    if ($^O eq "linux") {
        $sans_shell="/sbin/nologin";
        $result = 0;
    } elsif ($^O eq "solaris") {
        $sans_shell="/bin/false";
        $result = 0;
    } else {
        $sans_shell="";
        return 1;
    }

    if (!user_exists($username)) {
        return $result;
    }

    my ($name, $passwd, $uid, $gid, $quota,
        $comment, $gcos, $dir, $shell, $expire) = getpwnam($username);

    if (!$shell) {
        $result = 1;
    } elsif ($shell eq $sans_shell) {
        $result = 1;
    } else {
        # issue a warning and continue
        emit("WARNING:  Potential security hole - user '$username' is\n"
           . "          using '$shell' instead of '$sans_shell'!\n", "warning");
    }

    return $result;
}


# return 1 - is a member, or
# return 0 - is NOT a member
sub user_is_a_member_of_group
{
    my ($username, $groupname) = @_;

    return 0 if !user_exists($username);
    return 0 if !group_exists($groupname);

    # The members list returned by getgrname may not contain the user's primary group.
    # This is OS dependent and is typically the case when the primary gid is a
    # "user private group". Therefore testing the group member list is insufficient,
    # we must also test the primary group.
    my ($pw_name, $pw_passwd, $pw_uid, $pw_gid) = getpwnam($username);
    if (defined $pw_gid) {
        my $primary_groupname = getgrgid($pw_gid);

        return 1 if $primary_groupname eq $groupname;
    }

    # Now get the list of users in the specified group
    # and test to see if the specified user is in that list.
    my ($gr_name, $gr_passwd, $gr_gid, $gr_members) = getgrnam($groupname);
    for my $member (split(' ', $gr_members)) {
        return 1 if $member eq $username;
    }

    return 0;
}


# return 1 - success, or
# return 0 - failure
sub add_user_as_a_member_of_group
{
    my ($username, $groupname) = @_;

    my $command = "";
    my $result = 0;

    emit(sprintf("add_user_as_a_member_of_group(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    return 0 if !user_exists($username);
    return 0 if !group_exists($groupname);
    return 1 if user_is_a_member_of_group($username, $groupname);

        # Attempt to add user to be a member of group
        emit("Adding user '$username' to be a member of group "
            . "'$groupname'.\n", "debug");
        if ($^O eq "linux") {
            $command = "/usr/sbin/usermod "
                     . "-G $groupname "
                     . $username;
        } elsif ($^O eq "solaris") {
            $command = "/usr/sbin/usermod "
                     . "-G $groupname "
                     . $username;
        } else {
            $command = "/usr/sbin/usermod "
                     . "-G $groupname "
                     . $username;
        }

    return 0 if !run_command($command);
    return user_is_a_member_of_group($username, $groupname);
}


# return UID, or
# return (-1) - user is not in password file
sub get_UID_from_username
{
    my ($username) = @_;

    my ($name, $passwd, $uid) = getpwnam($username);

    return $uid if defined($uid);
        return (-1);
    }


# Return fully-qualified domain name (FQDN) given
# either a hostname or an IP address
sub get_FQDN
{
    my ($addr) = @_;

    if (!$is_IPv6) {
        if ($addr !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
            # Retrieve FQDN via a "mnemonic" hostname
            ($fqdn) = gethostbyname($addr);
        } else {
            # Retrieve FQDN via a "4-tuple" IP address
            $fqdn = gethostbyaddr(pack('C4', $1, $2, $3, $4), 2);
        }
    } else {
        # IPv6:  Don't rely upon "Socket6.pm" being present!
        $fqdn = $addr;
    }

    return($fqdn);
}


##############################################################
# Generic "availability" Subroutines
##############################################################

# return 1 - URL prefix is known (success)
# return 0 - URL prefix is unknown (failure)
sub check_for_valid_url_prefix
{
    my ($url_prefix) = @_;

    if (($url_prefix eq $FILE_PREFIX) || 
        ($url_prefix eq $FTP_PREFIX) || 
        ($url_prefix eq $HTTP_PREFIX) || 
        ($url_prefix eq $HTTPS_PREFIX) || 
        ($url_prefix eq $LDAP_PREFIX) || 
        ($url_prefix eq $LDAPS_PREFIX)) {
        return 1;
    }

    return 0;
}

# return 1 - ports are valid (success)
# return 0 - ports have a conflict (failure)
sub AreConnectorPortsValid 
{
    # parse parameters
    my ($secure_port, $unsecure_port, $agent_secure_port, 
        $ee_secure_port, $admin_secure_port, $proxy_secure_port, 
        $proxy_unsecure_port, $ajp_port) = @_;


    if ($secure_port == -1 && $agent_secure_port == -1)
    {
        return 0;
    }

    if ($secure_port >= 0 && $agent_secure_port >= 0)
    {
        return 0;
    }

    if ($secure_port >= 0)
    {
        if ($secure_port == $unsecure_port)
        {
             return 0;
        }
        return 1;
    }

    if (!portsUnique($agent_secure_port,$ee_secure_port, $admin_secure_port, $proxy_secure_port, 
        $proxy_unsecure_port, $ajp_port)) {
        return 0;
    }

    return 1;

}

#return 1 - if non-negative ports are uique
#return 0 - otherwise (failure)
sub portsUnique
{
   my @ports = sort @_;
   my $last_port = -1;
   for my $port (@ports) {
       next if ($port < 0);
       if ($port == $last_port) {
           return 0;
       }
       $last_port = $port;
   }
   return 1;
}

# return 1 - port is available (success)
# return 0 - port is unavailable; report an error (failure)
sub IsLocalPortAvailable
{
    # parse parameters
    my ($user, $port) = @_;

    # On Linux/UNIX, check well-known/reserved ports
    if (!is_Windows()) {
        my $uid = -1;

        # retrieve the UID given the username
        $uid = get_UID_from_username($user);
        if ($uid == -1) {
            emit("User '$user' is NOT in the password file!\n", "error");
            return 0;
        }

        # insure that well-known ports cannot be used by a non-root user
        if (($port <= $MAX_WELL_KNOWN_PORT) && ($uid != $ROOTUID)) {
            emit("User '$user' is not allowed to bind to well-known "
                 . "port $port!\n", "error");
            return 0;
        }

        # insure that reserved ports cannot be used by a non-root user
        if (($port <= $MAX_RESERVED_PORT) && ($uid != $ROOTUID)) {
            emit("User '$user' is not allowed to bind to reserved "
                 . "port $port!\n", "error");
            return 0;
        }

        # insure that the user has not specified a port greater than
        # the number of dynamic/private ports
        if ($port > $MAX_DYNAMIC_PORT) {
            emit("User '$user' is not allowed to bind to a "
                 . "port greater than $MAX_DYNAMIC_PORT!\n", "error");
            return 0;
        }

        # if the user has specified a port greater than the number
        # of registered ports, issue a warning and continue
        if ($port > $MAX_REGISTERED_PORT) {
            emit("WARNING:  User '$user' is binding to port $port; use of "
                 . "a dynamic/private port is discouraged!\n", "warning");
        }
    }

    # initialize local variables
    my $rv = 0;
    my $status = "AVAILABLE";

    # make a local TCP server socket
    my $proto = getprotobyname('tcp');
    socket(SERVER, PF_INET, SOCK_STREAM, $proto);

    # create a local server socket address
    my $server_address = sockaddr_in($port, INADDR_ANY);

    # attempt to bind this local server socket
    # to this local server socket address
    bind(SERVER, $server_address) or $status = $!;

    # identify the status of this attempt to bind
    if ($status eq "AVAILABLE") {
        # this port is inactive
        $rv = 1;
    } elsif ($status eq "Address already in use") {
        emit("Unable to bind to local port $port :  $status\n", "error");
        $rv = 0;
    } else {
        emit("Unable to bind to local port $port :  $status\n", "error");
        $rv = 0;
    }

    # close local server socket
    close(SERVER);

    # return result
    return $rv;
}


# return 2 - warn that server is unreachable (continue)
# return 1 - server is reachable (success)
# return 0 - server is unreachable; report an error (failure)
sub IsServerReachable
{
    # parse parameters
    my ($prefix, $host, $port) = @_;

    # check the validity of the prefix
    my $result = 0;

    $result = check_for_valid_url_prefix($prefix);
    if (!$result) {
        emit("Specified unknown url prefix '$prefix'!\n", "error");
        return $result;
    }

    # create a URL from the passed-in parameters
    my $url = $prefix . $host . ":" . $port;

    # initialize the state of the Server referred to by this URL
    my $rv = 0;
    my $status = "ACTIVE";

    # retrieve the remote host IP address
    my $iaddr = inet_aton($host) or $status = $!;
    if ($status ne "ACTIVE") {
        emit("Unable to contact the Server at '$url' ($status)", "error");
        return $rv;
    }

    # create a remote server socket address
    my $server_address = sockaddr_in($port, $iaddr);

    # make a local TCP client socket
    my $proto = getprotobyname('tcp');
    socket(CLIENT, PF_INET, SOCK_STREAM, $proto);

    # attempt to connect this local client socket
    # to the remote server socket address
    connect(CLIENT, $server_address) or $status = $!;

    # identify the status of this connection
    if ($status eq "ACTIVE") {
        # this '$host:$port' is reachable
        $rv = 1;
    } else {
        emit("WARNING:  Unable to contact the Server at '$url' ($status)", "warning");
    }

    # close local client socket
    close(CLIENT);

    # return result
    return $rv;
}


##############################################################
# Generic "time" Subroutines
##############################################################

# no args
# return time stamp
sub get_time_stamp
{
    my ($sec, $min, $hour, $mday,
        $mon, $year, $wday, $yday, $isdst) = localtime(time);

    my $stamp = sprintf "%4d-%02d-%02d %02d:%02d:%02d",
                        $year+1900, $mon+1, $mday, $hour, $min, $sec;

    return $stamp;
}


##############################################################
# Generic "random" Subroutines
##############################################################

# return random number between low & high
sub generate_random
{
    my ($low, $high) = @_;

    my $number = 0;

    if ($low >= $high || $low < 0 || $high < 0) {
        return -1;
    }

    $number = int(rand($high -$low +1)) + $low;

    return $number;
}


# return random string of specified length
sub generate_random_string
{
    my ($length_of_randomstring) = @_;

    my @chars=('a'..'z','A'..'Z','0'..'9');
    my $random_string;

    foreach (1..$length_of_randomstring) {
        $random_string .= $chars[rand @chars];
    }

    return $random_string;
}


##############################################################
# Generic "password" Subroutines
##############################################################

# return 1 - success
# return 0 - failure; report an error
sub password_quality_checker
{
    my ($password) = @_;
    my ($i, $letter);

    # Test #1:  $password MUST be > 8 characters
    if (length($password) < 8) {
        print("\n");
        print("Password entered is less than 8 characters. Try again.\n");
        return 0;
    }


    # Test #2:  $password MUST contain at least one non-alphabetic character
    my @alphabet = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
                     "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
                     "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d",
                     "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
                     "o", "p", "q", "r", "s", "t", "u", "v", "w", "x",
                     "y", "z");

    my $non_alphabetic_characters = 0;
    for ($i = 0; $i < length($password); $i++) {
        # always reset character type
        my $found_alphabetic_character = 0;

        # extract the next character from the $password
        my $character = substr($password, $i, 1);

        # check to see if this character is "alphabetic"
        for $letter (@alphabet) {
            if ($character eq $letter) {
                $found_alphabetic_character = 1;
                last;
            }
        }

        # keep a count of "non-alphabetic" characters
        if ($found_alphabetic_character == 0) {
            $non_alphabetic_characters++;
        }
    }

    # pass Test #2 if the $password contains any "non-alphabetic" characters
    if ($non_alphabetic_characters > 0) {
        return 1;
    } else {
        print("\n");
        print("Password entered contains 0 non-alphabetic characters. "
             . "Try again.\n");
        return 0;
    }
}


##############################################################
# Generic "LDAP" Subroutines
##############################################################

# hostname - LDAP server name or IP address (default: localhost)
# port - LDAP server TCP port number (default: 389)
# password - bind passwd (for simple authentication)
# file - read modifications from file (default: standard input)
# no return value
sub LDAP_add
{
    my ($tokendb_hostname, $tokendb_port, $tokendb_password, $file) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("LDAP_add(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    $command = "$default_ldapmodify_command "
             . "-h '$tokendb_hostname' "
             . "-p '$tokendb_port' "
             . "-D 'cn=directory manager' "
             . "-w '$tokendb_password' "
             . "-a "
             . "-f '$file'";

    system($command);

    set_library_path([$original_library_path]);

    return;
}


# hostname - LDAP server name or IP address (default: localhost)
# port - LDAP server TCP port number (default: 389)
# password - bind passwd (for simple authentication)
# file - read modifications from file (default: standard input)
# no return value
sub LDAP_modify
{
    my ($tokendb_hostname, $tokendb_port, $tokendb_password, $file) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("LDAP_modify(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    $command = "$default_ldapmodify_command "
             . "-h '$tokendb_hostname' "
             . "-p '$tokendb_port' "
             . "-D 'cn=directory manager' "
             . "-w '$tokendb_password' "
             . "-f '$file'";

    system($command);

    set_library_path([$original_library_path]);

    return;
}


##############################################################
# Generic "Security Databases" Subroutines
##############################################################

# instance path - Security databases directory (default is ~/.netscape)
# password file - Specify the password file
# no return value
sub certutil_create_databases
{
    my ($instance_path, $pwdfile) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("certutil_create_databases(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    if (!$pwdfile) {
        $command = "$default_certutil_command "
                 . "-N "
                 . "-d $instance_path";
    } else {
        $command = "$default_certutil_command "
                 . "-N "
                 . "-d $instance_path "
                 . "-f $pwdfile";
    }

    system($command);

    set_library_path([$original_library_path]);

    return;
}


# instance path - Security databases directory (default is ~/.netscape)
# token - Name of token in which to look for cert (default is internal,
#              use "all" to look for cert on all tokens)
# nickname - The nickname of the cert to delete
# no return value
sub certutil_delete_cert
{
    my ($instance_path, $token, $nickname) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("certutil_delete_cert(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    $command = "$default_certutil_command "
             . "-D "
             . "-d $instance_path "
             . "-h '$token' "
             . "-n '$nickname'";

    system($command);

    set_library_path([$original_library_path]);

    return;
}


# instance path - Security databases directory (default is ~/.netscape)
# token - Name of token in which to generate key (default is internal)
# subject - Specify the subject name (using RFC1485)
# password file - Specify the password file
# no return value
sub certutil_generate_CSR
{
    my ($instance_path, $token, $subject, $pwdfile) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("certutil_generate_CSR(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    if (!$pwdfile) {
        $command = "$default_certutil_command "
                 . "-R "
                 . "-d $instance_path "
                 . "-h '$token' "
                 . "-s '$subject' "
                 . "-a";
    } else {
        $command = "$default_certutil_command "
                 . "-R "
                 . "-d $instance_path "
                 . "-h '$token' "
                 . "-s '$subject' "
                 . "-a "
                 . "-f $pwdfile";
    }

    system($command);

    set_library_path([$original_library_path]);

    return;
}


# instance path - Security databases directory (default is ~/.netscape)
# token - Name of token in which to store the certificate
#              (default is internal)
# serial number - Cert serial number
# validity period - Months valid (default is 3)
# subject - Specify the subject name (using RFC1485)
# issuer name - The nickname of the issuer cert
# nickname - Specify the nickname of the server certificate
# trust args - Set the certificate trust attributes:
#                        p      valid peer
#                        P      trusted peer (implies p)
#                        c      valid CA
#                        T      trusted CA to issue client certs (implies c)
#                        C      trusted CA to issue server certs (implies c)
#                        u      user cert
#                        w      send warning
#                        g      make step-up cert
# noise file - Specify the noise file to be used
#                   (to introduce randomness during key generation)
# password file - Specify the password file
# no return value
sub certutil_generate_self_signed_cert
{
    my ($instance_path, $token, $serial_number, $validity_period,
        $subject, $issuer_name, $nickname, $trustargs, $noise_file,
        $pwdfile) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("certutil_generate_self_signed_cert(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    if (!$pwdfile) {
        $command = "$default_certutil_command "
                 . "-S "
                 . "-d $instance_path "
                 . "-h '$token' "
                 . "-m $serial_number "
                 . "-v $validity_period "
                 . "-x "
                 . "-s '$subject' "
                 . "-c '$issuer_name' "
                 . "-n '$nickname' "
                 . "-t '$trustargs' "
                 . "-z $noise_file "
                 . "> /dev/null "
                 . "2>&1";
    } else {
        $command = "$default_certutil_command "
                 . "-S "
                 . "-d $instance_path "
                 . "-h '$token' "
                 . "-f $pwdfile "
                 . "-m $serial_number "
                 . "-v $validity_period "
                 . "-x "
                 . "-s '$subject' "
                 . "-c '$issuer_name' "
                 . "-n '$nickname' "
                 . "-t '$trustargs' "
                 . "-z $noise_file "
                 . "> /dev/null "
                 . "2>&1";
    }

    system($command);

    set_library_path([$original_library_path]);

    return;
}


# instance path - Security databases directory (default is ~/.netscape)
# token - Name of token in which to store the certificate
#              (default is internal)
# nickname - Specify the nickname of the server certificate
# trust args - Set the certificate trust attributes:
#                        p      valid peer
#                        P      trusted peer (implies p)
#                        c      valid CA
#                        T      trusted CA to issue client certs (implies c)
#                        C      trusted CA to issue server certs (implies c)
#                        u      user cert
#                        w      send warning
#                        g      make step-up cert
#                    (e. g. - Server Cert 'u,u,u', CA Cert 'CT,CT,CT')
# cert - The certificate encoded in ASCII (RFC1113)
# no return value
sub certutil_import_cert
{
    my ($instance_path, $token, $nickname, $trustargs, $cert) = @_;

    my $original_library_path = get_library_path();

    emit(sprintf("certutil_import_cert(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    open(F,
          "|$default_certutil_command "
        . "-A "
        . "-d $instance_path "
        . "-h '$token' "
        . "-n '$nickname' "
        . "-t '$trustargs' "
        . "-a");
    print(F $cert);
    close(F);

    set_library_path([$original_library_path]);

    return;
}


# instance path - Security databases directory (default is ~/.netscape)
# token - Name of token in which to look for cert (default is internal,
#              use "all" to look for cert on all tokens)
# nickname - Pretty print named cert (list all if unspecified)
# no return value
sub certutil_print_cert
{
    my ($instance_path, $token, $nickname) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("certutil_print_cert(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    if ($token) {
        # Raidzilla Bug #57616 - certutil is not being consistent, nickname 
        #                        requires token name for no reason.
        $command = "$default_certutil_command "
                 . "-L "
                 . "-d $instance_path "
                 . "-h '$token' "
                 . "-n '$token:$nickname'";
    } else {
        $command = "$default_certutil_command "
                 . "-L "
                 . "-d $instance_path "
                 . "-h '$token' "
                 . "-n '$nickname'";
    }

    system($command);

    set_library_path([$original_library_path]);

    return;
}


# no return value
# instance path - Security databases directory (default is ~/.netscape)
# token - Name of token in which to look for certs (default is internal,
#              use "all" to list certs on all tokens)
sub certutil_list_certs
{
    my ($instance_path, $token) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("certutil_list_certs(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    $command = "$default_certutil_command "
             . "-L "
             . "-d $instance_path "
             . "-h '$token'";

    system($command);

    set_library_path([$original_library_path]);

    return;
}


# instance path - Security databases directory (default is ~/.netscape)
# token   - Add the named token to the module database
# library - The name of the file (.so or .dll) containing the
#                implementation of PKCS #11
# no return value
sub modutil_add_token
{
    my ($instance_path, $token, $library) = @_;

    my $command = "";

    my $original_library_path = get_library_path();

    emit(sprintf("modutil_add_token(%s)\n", join(", ", @_)), "debug");

    return if $dry_run;

    set_library_path([$default_security_libraries,
                      $default_system_user_libraries,
                      $default_system_libraries,
                      $original_library_path]);

    $command = "$default_modutil_command "
             . "-force "
             . "-dbdir $instance_path "
             . "-add $token "
             . "-libfile $library "
             . "-nocertdb";

    system("$command > /dev/null 2>&1");

    set_library_path([$original_library_path]);

    return;
}


##############################################################
# Generic "logging" Subroutines
##############################################################

# Return 1 if success, 0 if failure
sub open_logfile
{
    my ($path, $permissions, $owner, $group) = @_;

    
    $logfd = FileHandle->new("> $path");

    if (defined($logfd)) {
        $logfile_path = $path;
    } else {
        return 0;
    }

    if (defined($permissions)) {
        return 0 if !set_permissions($logfile_path, $permissions);
    }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group($logfile_path, $owner, $group);
    }

    return 1;
}

# no return value
sub get_logfile_path
{
    return $logfile_path;
}

# no return value
sub close_logfile
{
    if (defined($logfd)) {
        $logfd->close();
    }

    $logfd = undef;
    return;
}


##############################################################
# Generic "response" Subroutines
##############################################################

# return answer
sub prompt
{
    my ($promptStr) = @_;

    my $answer = "";

    print(STDOUT "$promptStr  ");

    $| = 1;
    $answer = <STDIN>;

    chomp $answer;

    print(STDOUT "\n");

    return $answer;
}


##############################################################
# Generic "reply" Subroutines
##############################################################

# no return value
sub printFile
{
    my ($fileHandle) = @_;

    while (<$fileHandle>) {
        my $line = $_;
        chomp($line);
        print(STDOUT "$line\n");
    }

    return;
}


# no return value
sub emit
{
    my ($string, $type) = @_;

    my $force_emit = 0;
    my $log_entry = "";

    $type = "debug" if !defined($type);

    if ($type eq "error" || $type eq "warning" || $type eq "info") {
        $force_emit = 1;
    }

    return if !$string;

    chomp($string);
    my $stamp = get_time_stamp();

    if ($verbose || $force_emit) {
        # print to stdout
        if ($type ne "log") {
            print(STDERR "[$type] $string\n");
        }
    }

    # If a log file exists, write all types
    # ("debug", "error", "info", or "log")
    # to this specified log file
    if (defined($logfd)) {
        $log_entry = "[$stamp] [$type] $string\n";
        $logfd->print($log_entry);
    }

    return;
}


##############################################################
# Generic "validity" Subroutines
##############################################################

# return 1 - valid, or
# return 0 - invalid
sub is_path_valid
{
    my ($path) = @_;

    my @pathname = split("/", $path);

    shift @pathname unless $pathname[0];

    my $valid = 0;
    my $split_path;

    foreach $split_path (@pathname) {
        chomp($split_path);

        if (!($split_path !~ /^[-_.a-zA-Z0-9\[\]\@]+$/)) {
            $valid = 1;
        } else {
            $valid = 0;
            last;
        }
    }

    return $valid;
}


# return 1 - valid, or
# return 0 - invalid
sub is_name_valid
{
    my ($name) = @_;

    my $result = 0;

    if (!($name !~ /^[-_.a-zA-Z0-9]+$/)) {
        $result = 1;
    }

    return $result;
}


##############################################################
# Generic "entity" Subroutines
##############################################################

# return type of entity
sub entity_type
{
    my ($entity) = @_;

    if (-b $entity) {
        return "block special file";
    } elsif (-c $entity) {
        return "character special file";
    } elsif (-d $entity) {
        return "directory";
    } elsif (-f $entity) {
        if (-B $entity) {
            return "binary file";
        } elsif (-T $entity) {
            return "text file";
        } else {
            return "plain file";
        }
    } elsif (-l $entity) {
        return "symbolic link";
    } elsif (-p $entity) {
        return "named pipe";
    } elsif (-S $entity) {
        return "socket";
    }

    return "UNKNOWN";
}


# return 1 - exists, or
# return 0 - DOES NOT exist
sub entity_exists
{
    my ($entity) = @_;

    my $result = 0;

    if (-e $entity) {
        my $type = entity_type($entity);
        $result = 1;
    }

    return $result;
}


##############################################################
# Generic "file" Subroutines
##############################################################

# return 1 - exists, or
# return 0 - DOES NOT exist
sub file_exists
{
    my ($file) = @_;

    my $result = 0;

    if (-f $file) {
        $result = 1;
    } elsif (-e $file) {
        my $type = entity_type($file);
        emit("File $file DOES NOT exist because $file is a $type!\n",
              "error");
        $result = 0;
    }


    return $result;
}


# return 1 - empty, or
# return 0 - NOT empty
sub is_file_empty
{
    my ($file) = @_;

    my $result = 0;

    if (-z $file) {
        $result = 1;
    }

    return $result;
}


# Return 1 if success, 0 if failure
sub create_empty_file
{
    my ($path, $permissions, $owner, $group, $uninstall_action) = @_;

    $uninstall_action = 'remove' unless defined($uninstall_action);

    emit(sprintf("create_empty_file(%s, %s, %s, %s, %s)\n",
                 $path,
                 defined($permissions) ? sprintf("%o", $permissions) : "",
                 $owner, $group, $uninstall_action), "debug");

    add_install_info($path, 'file', $uninstall_action);

    if (!$dry_run) {
        if (!open(FILE, "> $path")) {
            emit("Cannot create empty file \"$path\" ($!)", 'error');
            return 0;
        }
        close(FILE);
    }

    if (defined($permissions)) {
        return 0 if !set_permissions($path, $permissions);
    }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group($path, $owner, $group);
    }

    return 1;
}


# Return 1 if success, 0 if failure
sub create_file
{
    my ($path, $contents, $permissions, $owner, $group, $uninstall_action) = @_;

    $uninstall_action = 'remove' unless defined($uninstall_action);

    emit(sprintf("create_file(%s, %s, %s, %s, %s)\n",
                 $path,
                 defined($permissions) ? sprintf("%o", $permissions) : "",
                 $owner, $group, $uninstall_action), "debug");

    add_install_info($path, 'file', $uninstall_action);

    if (!$dry_run) {
        if (!open(FILE, "> $path")) {
            emit("could not create file \"$path\" ($!)\n", 'error');
            return 0;
        }
        print(FILE $contents);
            close(FILE);
        }

    if (defined($permissions)) {
        return 0 if !set_permissions($path, $permissions);
            }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group($path, $owner, $group);
    }

    return 1;
}


# Return 1 if success, 0 if failure
sub copy_file
{
    my ($src_path, $dst_path, $permissions, $owner, $group, $uninstall_action) = @_;

    $uninstall_action = 'remove' unless defined($uninstall_action);

    emit(sprintf("copy_file(%s, %s, %s, %s, %s, %s)\n",
                 $src_path, $dst_path,
                 defined($permissions) ? sprintf("%o", $permissions) : "",
                 $owner, $group, $uninstall_action), "debug");

    add_install_info($dst_path, 'file', $uninstall_action);

    if (!is_path_valid($src_path)) {
        emit("copy_file():  illegal src path => \"$src_path\".\n",
              "error");
        remove_install_info($dst_path);
        return 0;
    }

    if (!is_path_valid($dst_path)) {
        emit("copy_file():  illegal dst path => \"$dst_path\".\n",
              "error");
        remove_install_info($dst_path);
        return 0;
    }

    if (!$dry_run) {
        if (!copy($src_path, $dst_path)) {
            emit("copy_file(): \"$src_path\" => \"$dst_path\" ($!)\n", "error");
            remove_install_info($dst_path);
        return 0;
    }
    }

    if (defined($permissions)) {
        return 0 if !set_permissions($dst_path, $permissions);
    }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group($dst_path, $owner, $group);
    }

    return 1;
}


# Return 1 if success, 0 if failure
sub remove_file
{
    my ($path) = @_;
    my $result = 0;

    emit(sprintf("remove_file(%s)\n", join(", ", @_)), "debug");

    add_install_info($path, 'file', 'remove', 'remove');

    return 1 if $dry_run;

    if (!unlink($path)) {
        emit("remove_file(): failed to remove file \"$path\" ($!)\n", "error");
        return 0;
    }

        return 1;
    }

# set_permissions(path_glob, permissions)
# Return 1 if success, 0 if failure
sub set_permissions
{
    my ($path_glob, $permissions) = @_;
    my (@paths, $errstr, $result, $count);

    $errstr = undef;
    $count = 0;
    $result = 1;

    emit(sprintf("set_permissions(%s, %s)\n",
                 $path_glob,
                 defined($permissions) ? sprintf("%o", $permissions) : ""), "debug");

    return 1 if $dry_run;

    @paths = glob($path_glob);

    if (($count = chmod($permissions, @paths)) != @paths) {
        $errstr = "$!";
        $result = 0;
        emit(sprintf("failed to set permission (%o) on \"%s\" => (%s), %d out of %d failed, \"%s\"\n",
                     $permissions, $path_glob, "@paths", @paths - $count, @paths+0, $errstr), 'error');
    }
    return $result;
    }

# set_owner_group(path_glob, owner, group)
# Return 1 if success, 0 if failure
sub set_owner_group
{
    my ($path_glob, $owner, $group) = @_;
    my (@paths, $errstr, $result, $count);
    my ($uid, $gid);

    $errstr = undef;
    $count = 0;
    $result = 1;

    emit(sprintf("set_owner_group(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    $uid   = getpwnam($owner);
    $gid   = getgrnam($group);
    @paths = glob($path_glob);

    if (($count = chown($uid, $gid, @paths)) != @paths) {
        $errstr = "$!";
        $result = 0;
        emit(sprintf("failed to set ownership (%s) on \"%s\" => (%s), %d out of %d failed, \"%s\"\n",
                     "${owner}:${group}", $path_glob, "@paths", @paths - $count, @paths+0, $errstr), 'error');
    }
    return $result;
}

# set_file_props(path_glob, permissions, owner, group)
# Return 1 if success, 0 if failure
sub set_file_props
{
    my ($path_glob, $permissions, $owner, $group) = @_;
    my (@paths, $tmp_result, $result);

    $result = 1;

    emit(sprintf("set_file_props(%s %s %s %s)\n",
                 $path_glob,
                 defined($permissions) ? sprintf("%o", $permissions) : "",
                 $owner, $group), "debug");

    return 1 if $dry_run;

    $tmp_result = set_permissions($path_glob, $permissions);
    $result = 0 if !$tmp_result;

    $tmp_result = set_owner_group($path_glob, $owner, $group);
    $result = 0 if !$tmp_result;

    return $result;
    }



##############################################################
# Generic "directory" Subroutines
##############################################################

# Callback for walk_dir(), see walk_dir() for documentation
sub walk_callback {
  my ($dir, $basename, $is_dir, $prune, $opts) = @_;

    if ($is_dir) {
	my ($include_dirs, $mark_dir, $add_to_list, $regexp, $regexps);
	
	# Don't descend into directories unless recursive.
	$$prune = ! $opts->{'recursive'};

	# If include filter is provided, basename must match
	# at least one regexp in filter list.
	if (defined($regexps = $opts->{'dir_includes'})) {
	    $add_to_list = 0;
	    for $regexp (@$regexps) {
		if ($basename =~ /$regexp/) {
		    $add_to_list = 1;
		    last;
		}
	    }
	} else {
	    $add_to_list = 1;
	}

	if (!$add_to_list) {
	    $$prune = 1;
	    return;
	}

	# If exclude filter is provided, basename cannot match
	# any regexp in filter list.
	if (defined($regexps = $opts->{'dir_excludes'})) {
	    for $regexp (@$regexps) {
		if ($basename =~ /$regexp/) {
		    $add_to_list = 0;
		    last;
		}
	    }
	}

	if (!$add_to_list) {
	    $$prune = 1;
	    return;
	}

	# Are we collecting directories?
	$include_dirs = $opts->{'include_dirs'} // 0;
	return if ! $include_dirs;

	if ($opts->{'mark_dir'}) {
	    push(@{$opts->{'file_list'}}, "${dir}/${basename}/");
	} else {
	    push(@{$opts->{'file_list'}}, "${dir}/${basename}");
	}
    }
    else {
	my ($include_files, $add_to_list, $regexp, $regexps);
	
	# If include filter is provided, basename must match
	# at least one regexp in filter list.
	if (defined($regexps = $opts->{'file_includes'})) {
	    $add_to_list = 0;
	    for $regexp (@$regexps) {
		if ($basename =~ /$regexp/) {
		    $add_to_list = 1;
		    last;
		}
	    }
	} else {
	    $add_to_list = 1;
	}

	return if !$add_to_list;

	# If exclude filter is provided, basename cannot match
	# any regexp in filter list.
	if (defined($regexps = $opts->{'file_excludes'})) {
	    for $regexp (@$regexps) {
		if ($basename =~ /$regexp/) {
		    $add_to_list = 0;
		    last;
		}
	    }
	}

	return if !$add_to_list;

	# Are we collecting files?
	$include_files = $opts->{'include_files'} // 0;
	return if ! $include_files;

	push(@{$opts->{'file_list'}}, "${dir}/${basename}");
    }
}

# Walk directory structure invoking a callback on each
# item found. Optionally prune traversal.
#
# walk_dir($dir, $callback, $prune, $user_data)
#
# dir      Path of directory to examine.
# callback Pointer to callback function.
# prune    Pointer to boolean variable.
#          Callback can set to avoid descending into a directory.
#          Ignored for non-directory callback invocations.
# opts     Hash table of key/value pairs which controls execution and
#          can be used to pass user values to the walk callback.
#          See get_directory_files() for definitions.
#
# The signature of the callback is:
#
# callback($dir, $basename, $is_dir, $prune, $user_data)
#
# dir      Current directory path.
# basename Entry in directory.
# is_dir   Boolean, true if basename is a directory
# prune    Pointer to boolean variable.
#          Callback can set to avoid descending into a directory.
#          Ignored for non-directory callback invocations.
# opts     Hash table of key/value pairs which controls execution and
#          can be used to pass user values to the walk callback.
#          See get_directory_files() for definitions.
#
sub walk_dir {
  my ($dir, $callback, $prune, $opts) = @_;
  my ($basename);

  # Get the list of files in the current directory.
  opendir(DIR, $dir) || (warn "Can't open $dir: $!\n", return);
  my (@entries) = sort readdir(DIR);
  closedir(DIR);
    
  foreach $basename (@entries) {
    next if $basename eq '.';
    next if $basename eq '..';
    $$prune = 0;
	
    my $path = "${dir}/${basename}";
    if ((-d $path) &&
        ((! $opts->{'preserve_links'}) || (! -l $path))) { # yes it is a directory
      &$callback($dir, $basename, 1, $prune, $opts);
      if (!$$prune) {
	walk_dir($path, $callback, $prune, $opts);
      }
    }
    else {		# not a directory
      &$callback($dir, $basename, 0, $prune, $opts);
      last if $$prune;
    }
  }
}

# Given a directory path return a sorted array of it's contents.
# The opts parameter is a hash of key/value pairs which controls
# execution and can be used to pass user values to the walk callback.
#
# The options are:
#
# strip_dir (default = false)
#     If true strip the leading $dir from returned paths,
#     otherwise preserve $dir in each returned path.
# recursive (default = true)
#     If true then recusively descend into each directory,
#     otherwise just examine the starting directory
# preserve_links (default = true)
#     If true symbolic links are preserved.
#     If false symbolic links are traversed.
# include_dirs (default = false)
#     If true include directories in the returned array,
#     otherwise directories are omitted.
# include_files (default = true)
#     If true include files in the returned array,
#     otherwise files are omitted.
# mark_dir (default = false)
#     If true paths which are directories (include_dirs must be true)
#     are indicated by a trailing slash, otherwise the basename of
#     the directory is left bare.
#
# Filtering
#
# You may specify a set of include/exclude filters on both directories and
# files. An entry will be added to the returned list if it's in the include
# list and not in the exclude list. If either the include or exclude list
# is undefined it has no effect. Each filter is an array of regular
# expressions. The basename (directory entry) is tested against the regular
# expression. For the include filter the basename must match at least one
# of the regular expressions. For the exclude filter if the basename
# matches any of the regular expressions it will be excluded.
#
# In addition if the traversal is recursive and a directory is excluded via
# filtering then that directory is not descended into during the recursive
# traversal.
#
# dir_includes (default = undef)
#     Array of regular expressions. If defined a directory must match at
#     least one regular expression in the array to be included.
# dir_excludes (default = undef)
#     Array of regular expressions. If defined a directory will be excluded
#     if it matches any regular expression in the array.
# file_includes (default = undef)
#     Array of regular expressions. If defined a file must match at
#     least one regular expression in the array to be included.
# file_excludes (default = undef)
#     Array of regular expressions. If defined a file will be excluded
#     if it matches any regular expression in the array.
#
sub get_directory_files
{
    my ($dir, $opts) = @_;
    my ($strip_dir, $mark_dir, $recursive, $preserve_links, $include_dirs, $include_files);
    my ($dir_includes, $dir_excludes, $file_includes, $file_excludes);
    my ($files, $prune, $pat);

    $strip_dir      = $opts->{'strip_dir'}      // 0;
    $mark_dir       = $opts->{'mark_dir'}       // 0;
    $recursive      = $opts->{'recursive'}      // 1;
    $preserve_links = $opts->{'preserve_links'} // 1;
    $include_dirs   = $opts->{'include_dirs'}   // 0;
    $include_files  = $opts->{'include_files'}  // 1;
    $dir_includes   = $opts->{'dir_includes'}   // undef;
    $dir_excludes   = $opts->{'dir_excludes'}   // undef;
    $file_includes  = $opts->{'file_includes'}  // undef;
    $file_excludes  = $opts->{'file_excludes'}  // undef;

    $files = [];
    $prune = 0;

    walk_dir($dir, \&walk_callback, \$prune,
	     {'file_list'      => $files,
	      'mark_dir'       => $mark_dir,
	      'recursive'      => $recursive,
              'preserve_links' => $preserve_links,
	      'include_dirs'   => $include_dirs,
	      'include_files'  => $include_files,
	      'dir_includes'   => $dir_includes,
	      'dir_excludes'   => $dir_excludes,
	      'file_includes'  => $file_includes,
	      'file_excludes'  => $file_excludes,
	     });

    if ($strip_dir) {
        $pat = "^${dir}/";
        map {s/$pat//; $_} @$files;
    }
        
    return $files;
}

# Normalize paths such that:
#     Multiple slashes are collapsed into one slash
#     Trailing slash is stripped.
#     Strip "." path components.
#     Strip previous path component for ".."
# Returns normalized path.
sub normalize_path
{
    my ($path) = @_;
    my (@src_components, @dst_components, $component, $leading_slash, $new_path);

    $leading_slash = $path =~ m!^/! ? "/" : "";

    @src_components = split("/", $path);
    
    foreach $component (@src_components) {
        next if !$component;
        next if $component eq ".";
        if ($component eq "..") {
            die "no directory component to pop \"..\" for in \"$path\"" if !@dst_components;
            pop @dst_components;
            next;
        }
        push @dst_components, $component;
    }

    $new_path = join("/", @dst_components);

    return $leading_slash . $new_path;
}

# return 1 - exists, or
# return 0 - DOES NOT exist
sub directory_exists
{
    my ($dir) = @_;

    my $result = 0;

    if (-d $dir) {
        $result = 1;
    } elsif (-e $dir) {
        my $type = entity_type($dir);
        emit("Directory $dir DOES NOT exist because $dir is a $type!\n",
              "error");
        $result = 0;
    }

    return $result;
}


# return 1 - empty, or
# return 0 - NOT empty
sub is_directory_empty
{
    my ($dir) = @_;

    my $empty = 1;
    my $entity = "";

    if (!directory_exists($dir)) {
        return 1;
    }

    opendir(DIR, $dir);
    while (defined($entity = readdir(DIR)) && ($empty == 1)) {
        if ($entity ne "." && $entity ne "..") {
            # NOTE:  This is not necessarily an error!
            #
            # my $type = entity_type("$dir/$entity");
            # emit("    Found $type $entity in directory $dir.\n",
            #       "debug");

            $empty = 0;
        }
    }
    closedir(DIR);

    return $empty;
}


# Return 1 if success, 0 if failure
sub create_directory
{
    my ($dir, $permissions, $owner, $group, $uninstall_action) = @_;
    my $result = 1;
    my $errors;

    $uninstall_action = 'remove' unless defined($uninstall_action);

    emit(sprintf("create_directory(%s, %s, %s, %s, %s)\n",
                 $dir,
                 defined($permissions) ? sprintf("%o", $permissions) : "",
                 $owner, $group, $uninstall_action), "debug");

    add_install_info($dir, 'dir', $uninstall_action);

    return 1 if $dry_run;

    if (!directory_exists($dir)) {
        make_path($dir, {error => \$errors});
        if (@$errors) {
            my ($error, $path, $errstr);
            $result = 0;
            for $error (@$errors) {
                ($path, $errstr) = %$error;
                if ($path eq '') {
                    emit("create_directory(): dir=\"$dir\" \"$errstr\"\n", "error");
}
                else {
                    remove_install_info($path);
                    emit("create_directory(): dir=\"$dir\" path=\"$path\" \"$errstr\"\n", "error");
                }
            }
        }
    }

    if ($result) {
        if (defined($permissions)) {
            return 0 if !set_permissions($dir, $permissions);
        }

        if (defined($owner) && defined($group)) {
            return 0 if !set_owner_group($dir, $owner, $group);
        }
    }

    return $result;
}

# Return 1 if success, 0 if failure
sub copy_directory
{
    my ($src_dir_path, $dst_dir_path,
       $dir_permissions, $file_permissions,
       $owner, $group, $uninstall_action) = @_;
    my($result);
    my ($files, $sub_dirs, $path, $src_path, $dst_path);

    $uninstall_action = 'remove' unless defined($uninstall_action);
    $result = 1;

    $src_dir_path = normalize_path($src_dir_path);
    $dst_dir_path = normalize_path($dst_dir_path);

    emit(sprintf("copy_directory(%s, %s, %s, %s, %s, %s, %s)\n",
                 $src_dir_path, $dst_dir_path,
                 defined($dir_permissions) ? sprintf("%o", $dir_permissions) : "",
                 defined($dir_permissions) ? sprintf("%o", $dir_permissions) : "",
                 $owner, $group, $uninstall_action), "debug");

    if (!is_path_valid($src_dir_path)) {
        emit("copy_directory():  illegal src path => $src_dir_path.\n",
              "error");
        return 0;
    }

    if (!is_path_valid($dst_dir_path)) {
        emit("copy_directory(): illegal dst path ($dst_dir_path)\n", "error");
        return 0;
    }

    if (!directory_exists($src_dir_path)) {
        # Take the case where this directory does not exist
        # Just return true
        emit("copy_directory(): non-existent src path ($src_dir_path)\n", "error");
        return 1;
    }

    # Get list of directories under the src dir
    $sub_dirs = get_directory_files($src_dir_path,
                                    {'strip_dir' => 1, 'include_dirs' => 1, 'include_files' => 0});
    
    # Get list of files under the src dir
    $files = get_directory_files($src_dir_path,
                                 {'strip_dir' => 1, 'include_dirs' => 0, 'include_files' => 1});
    
    # Assure each destination directory exists
    return 0 if !create_directory($dst_dir_path,
                                  $dir_permissions, $owner, $group, $uninstall_action);
    for $path (@$sub_dirs) {
        $dst_path = "${dst_dir_path}/${path}";
        return 0 if !create_directory($dst_path, $dir_permissions,
                                      $owner, $group, $uninstall_action);
    }

    # Copy each file
    for $path (@$files) {
        $src_path = "${src_dir_path}/${path}";
        $dst_path = "${dst_dir_path}/${path}";
        
        # Emulate cp's behavior with respect to symbolic links,
        # symbolic links are NOT followed when copying recursively.
        # During recursive copies symbolic links are recreated.
        if (-l $src_path) {     # src is a symbolic link
            if (!copy_symlink($src_path, $dst_path, 
                                $owner, $group, $uninstall_action)) {
                $result = 0;
            }
        } else {                # src is not a symbolic link
            if (!copy_file($src_path, $dst_path, 
                           $file_permissions, $owner, $group, $uninstall_action)) {
                $result = 0;
            }
        }
    }

    if (!$result) {
        emit("copy_directory(): failed $src_dir_path => $dst_dir_path.\n",
             "error");
    }

    return $result;
}


# Removes given directory. By default only the directory is removed and
# only if it is empty. To remove the directory and all of it's contents
# you must provide the $remove_contents parameter and set it to true,
# it defaults to false.
#
# Return 1 if success, 0 if failure
sub remove_directory
{
    my($dir, $remove_contents) = @_;
    my($errors, $result);

    emit(sprintf("remove_directory(%s)\n", join(", ", @_)), "debug");

    $remove_contents = 0 unless defined($remove_contents);
    $result = 1;

    add_install_info($dir, 'dir', 'remove', 'remove');

    return 1 if $dry_run;

    if (!is_path_valid($dir)) {
        emit("remove_directory(): specified invalid directory $dir.\n",
              "error");
        return 0;
    }

    if ($dir eq "/") {
       emit("remove_directory(): don't even think about removing root!.\n",
             "error");
       return 0;
    }

    if (!directory_exists($dir)) {
        return 1;
    }

    if ($remove_contents) {
        remove_tree($dir, {error => \$errors});
        if (@$errors) {
            my($error, $path, $errstr);
            $result = 0;
            for $error (@$errors) {
                ($path, $errstr) = %$error;
                if ($path eq '') {
                    emit("remove_directory(): tree=\"$dir\" ($errstr)\n", "error");
                }
                else {
                    emit("remove_directory(): tree=\"$dir\" path=\"$path\" ($errstr)\n", "error");
                }
            }
        }
    } else {
        if (!rmdir($dir)) {
            $result = 0;
            emit("remove_directory(): dir=\"$dir\" ($!) \n", "error");
        }
    }

    return $result;
}


# Return 1 if success, 0 if failure
sub set_owner_group_on_directory_contents
{
    my ($dir, $owner, $group, $recursive) = @_;
    my ($result, $paths, $path);

    $recursive = $recursive // 1;
    $result = 1;

    emit(sprintf("set_owner_group_on_directory_contents(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    if (!$dir || !directory_exists($dir)) {
        emit("set_owner_group_on_directory_contents(): invalid directory specified.\n",
              "error");
        return 0;
    }

    if (!$owner || !$group) {
        emit("set_owner_group_on_directory_contents(): directory $dir needs a user and group!\n",
              "error");
        return 0;
    }

    $paths = get_directory_files($dir, {'recursive'    => $recursive,
                                        'include_dirs' => 1});

    for $path (@$paths) {
        $result = 0 if !set_owner_group($path, $owner, $group);
    }

    return $result;
}


##############################################################
# Generic "symbolic link" Subroutines
##############################################################

# return 1 - exists, or
# return 0 - DOES NOT exist
sub symlink_exists
{
    my ($symlink) = @_;

    my $result = 0;

    if (-l $symlink) {
        $result = 1;
    } elsif (-e $symlink) {
        my $type = entity_type($symlink);
        emit("Symbolic link $symlink DOES NOT exist because $symlink "
            . "is a $type!\n",
              "error");
        $result = 0;
    }


    return $result;
}


# Return 1 if success, 0 if failure
sub create_symlink
{
    my ($symlink, $dst_path, $owner, $group, $uninstall_action) = @_;

    $uninstall_action = 'remove' unless defined($uninstall_action);

    emit(sprintf("create_symlink(%s)\n", join(", ", @_)), "debug");

    add_install_info($symlink, 'symlink', $uninstall_action);

    return 1 if $dry_run;

    if (symlink_exists($symlink)) {
        # delete symbolic link so that we can recreate link for upgrades
        if (unlink($symlink) != 1) {
            emit("create_symlink(): could not remove existing link \"$symlink\"\n", 'error');
            remove_install_info($symlink);
            return 0;
        }
    }

    if (!is_path_valid($symlink)) {
        emit("create_symlink(): invalid path \"$symlink\"\n", "error");
        remove_install_info($symlink);
        return 0;
    }

    if (!is_path_valid($dst_path) || !entity_exists($dst_path)) {
        emit("create_symlink(): illegal dst path \"$dst_path\"\n", "error");
        remove_install_info($symlink);
        return 0;
    }

    if (!symlink($dst_path, $symlink)) {
        emit("create_symlink(): failed \"$symlink\" => \"$dst_path\" ($!)\n", "error");
        remove_install_info($symlink);
        return 0;
    }

    if (defined($owner) && defined($group)) {
        # The Perl Lchown package implements lchown, but it's not currently available
        # as an RPM so use a system command instead. :-(
        return 0 if !set_owner_group_on_symlink($symlink, $owner, $group);
    }
    return 1;
}

# Return 1 if success, 0 if failure
sub copy_symlink
{
    my ($src_path, $dst_path, $owner, $group, $uninstall_action) = @_;
    my ($target);

    $uninstall_action = 'remove' unless defined($uninstall_action);

    emit(sprintf("copy_symlink(%s)\n", join(", ", @_)), "debug");

    add_install_info($dst_path, 'symlink', $uninstall_action);

    if (!is_path_valid($src_path)) {
        emit("copy_symlink():  illegal src path => \"$src_path\".\n",
              "error");
        remove_install_info($dst_path);
        return 0;
    }

    if (!is_path_valid($dst_path)) {
        emit("copy_symlink():  illegal dst path => \"$dst_path\".\n",
              "error");
        remove_install_info($dst_path);
        return 0;
    }
    
    if (! -l $src_path) {
        emit("copy_symlink(): $src_path is not a symbolic link\n");
        return 0;
    }

    return 1 if $dry_run;

    $target = readlink($src_path);

    if (!symlink($target, $dst_path)) {
        emit("could not symbolically link $target dst_path", "error");
        remove_install_info($dst_path);
        return 0;
    }

    if (defined($owner) && defined($group)) {
        return 0 if !set_owner_group_on_symlink($dst_path, $owner, $group);
    }

    return 1;
}


# Return 1 if success, 0 if failure
sub remove_symlink
{
    my ($symlink) = @_;
    my $result = 0;

    emit(sprintf("remove_symlink(%s)\n", join(", ", @_)), "debug");

    add_install_info($symlink, 'symlink', 'remove', 'remove');

    return 1 if $dry_run;

    if (!$symlink) {
        # symlink is NULL
        return 1;
    }

    if (!symlink_exists($symlink)) {
        return 1;
    }

    if (unlink($symlink) != 1) {
        emit("remove_symlink(): failed \"$symlink\" ($!)\n", "error");
        return 0;
    }

    return 1;
}


# Return 1 if success, 0 if failure
sub set_owner_group_on_symlink
{
    my ($symlink, $owner, $group) = @_;

    emit(sprintf("set_owner_group_on_symlink(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    if (!$symlink || !symlink_exists($symlink)) {
        emit("set_owner_group_on_symlink(): invalid symbolic link specified \"$symlink\"\n",
              "error");
        return 1;
    }

    if (!$owner || !$group) {
        emit("set_owner_group_on_symlink(): symbolic link \"$symlink\" needs a user and group!\n",
              "error");
        return 0;
    }

    # The Perl Lchown package implements lchown, but it's not currently available
    # as an RPM so use a system command instead. :-(
    return run_command("chown --no-dereference ${owner}:${group} $symlink");
}


##############################################################
# Generic "chkconfig" Subroutines (Linux ONLY)
##############################################################

if ($^O eq "linux") {
    # Return 1 if success, 0 if failure
    sub register_pki_instance_with_chkconfig
    {
        my ($pki_instance_name) = @_;
        my ($command, $exit_status, $result);

        $result = 1;
        $command = "/sbin/chkconfig --add $pki_instance_name";
        if (run_command($command)) {
            emit("Registered '$pki_instance_name' with '/sbin/chkconfig'.\n");
        } else {
            $result = 0;
            emit("Failed to register '$pki_instance_name' with '/sbin/chkconfig'.\n", 'error');
        }
        return $result;
    }

    # Return 1 if success, 0 if failure
    sub deregister_pki_instance_with_chkconfig
    {
        my ($pki_instance_name) = @_;
        my ($command, $exit_status, $result);

        $result = 1;
        $command = "/sbin/chkconfig --del $pki_instance_name";
        if (run_command($command)) {
            emit("Registered '$pki_instance_name' with '/sbin/chkconfig'.\n");
        } else {
            $result = 0;
            emit("Failed to deregister '$pki_instance_name' with '/sbin/chkconfig'.\n", 'error');
        }
        return $result;
    }
}

##############################################################
# Generic Subprocess Subroutines
##############################################################

# Runs the supplied command in a sub-shell. The command is subject
# to shell interpretation.
#
# WARNING: Do not supply shell IO redirection in the command.
#
# Return 1 if success, 0 if failure
#
# The critical aspect of running a command is determining if the
# command succeeded or failed. The proper way to determine this is by
# checking exit status of command. Perl's subprocess mechansims are
# less than ideal. In simplicity you would want to run the subprocess,
# indpendently capture stdout & stderr, wait for termination and then
# get the exit status. However most of the mechanisms discard
# stderr. The advantages & disadvantages of each approach is nicely
# documented here:
#
# http://blog.0x1fff.com/2009/09/howto-execute-system-commands-in-perl.html
#
# Ideally we would like to capture stdout and stderr
# independently. The best way to do this is with Perl's IPC::Cmd
# package which is part of the standard Perl distribution (whose
# installation may be optional on a given system. RPM can detect our
# use of this package and force it's installation as a
# dependency). One disadvantage of IPC::Cmd is that it does not return
# the actual exit status, just an indication if it was non-zero or not
# (e.g. success). If we chose to use IPC::Cmd at a future date the
# implementation would look like this:
#
#    # Note: IPC::Cmd is in the perl-IPC-Cmd RPM
#    use IPC::Cmd qw[run];
#
#    my ($success, $error_code, $full_buf, $stdout_buf, $stderr_buf) =
#	run(command => $cmd, verbose => 0);
#
#    if (!$success) {
#        my ($err_msg);
#        
#        $err_msg = join("", @$stderr_buf);
#        chomp($err_msg);
#
#	emit(sprintf("FAILED run_command(\"%s\"), output=\"%s\"\n",
#                     $cmd, $err_msg), "error");
#
#	return 0;
#    }
#
sub run_command
{
    my ($cmd) = @_;
    my ($output, $wait_status, $exit_status);

    emit(sprintf("run_command(%s)\n", join(", ", @_)), "debug");

    return 1 if $dry_run;

    # Perl backtick only captures stdout.
    # stderr goes to the existing stderr file descriptor, probably the console.
    # Capture stderr along with stdout via shell redirection (e.g. 2>&1)

    $output = `$cmd 2>&1`;
    $wait_status = $?;

    # The low order 8 bits of the status is the terminating signal
    # for the process, the actual exit status is obtained by 
    # shifting the low order 8 bits out.
    $exit_status = $wait_status >> 8;

    if ($exit_status != 0) {
	chomp($output);
	emit(sprintf("FAILED run_command(\"%s\"), exit status=%d output=\"%s\"\n",
		     $cmd, $exit_status, $output), "error");
        return 0;
    }

    return 1;
}

##############################################################
# Generic Java Subroutines
##############################################################

# Given a jar's base name locate it in the file system
# using standard Java jar path for this system.
# Return the path to the jar if found, undef otherwise.
sub find_jar
{
    my($jar_name) = @_;
    my($jar_dir, $jar_path);

    for $jar_dir (@default_jar_path) {
        $jar_path = "$jar_dir/$jar_name";
        if (-e $jar_path) {
            return $jar_path;
        }
    }
    return undef;
}

##############################################################
# Generic PKI Subroutines
##############################################################

# Get parameter value(s) from CS.cfg file
#
# get_cs_cfg(config_path, search)
#
# There are 3 ways the parameters can be returned, as a string, as a
# set of variables, or as a hash table depending on the search
# parameter type.
#
# If search is string then the parameter value is returned as a string
# if it was found, otherwise if it wasn't found then undef is
# returned.
#
# If search is a reference to a hash then each key in the hash will be
# searched for and the key's value will be used as a reference to
# assign the value of the parameter to. If the key was not found then
# the reference will be assigned the value of undef.
#
# If search is reference to an array then every parameter in the
# array will be searched for and a hash will be returned with a key
# for every parameter found, the key's value is the parameter value.
#
# Examples:
#  
# my ($subsystem_type, $uri, $table);
#
# # Get a single string: $subsystem_type is assigned the string "CA"
# $subsystem_type = get_cs_cfg("/etc/pki-ca/CS.cfg", "cs.type");
#
# # Assign a set of variables: $subsystem_type and $uri are assigned
# get_cs_cfg($config_path, {"cs.type" => \$subsystem_type,
#                           "ee.interface.uri" => \$uri});
# 
# # Get a lookup table:
# $table = get_cs_cfg("/etc/pki-ca/CS.cfg", ["cs.type", "ee.interface.uri"]);
# # returns the hash:
# # {"cs.type"          => "CA",
# #  "ee.interface.uri" => "ca/ee/ca"}
#
sub get_cs_cfg
{
    my ($config_path, $search) = @_;
    my ($text, $key, $value, $num_found);

    $text = read_file($config_path);

    if (ref($search) eq "HASH") {
        my $num_found = 0;
        while (my ($key, $ref) = each(%$search)) {
            if ($text =~ /^\s*\Q$key\E\s*=\s*(.*)/m) {
                $value = $1;
                $$ref = $value;
                $num_found += 1;
            } else {
                $$ref = undef;
            }
        }
        return $num_found;
    } elsif (ref($search) eq "ARRAY") {
        my $result = {};
        my $keys = $search;

        foreach $key (@$keys) {
            if ($text =~ /^\s*\Q$key\E\s*=\s*(.*)/m) {
                $value = $1;
                $result->{$key} = $value;
            }
        }

        return $result;

    } else {
        my $result = undef;
        $key = $search;

        if ($text =~ /^\s*\Q$key\E\s*=\s*(.*)/m) {
            $value = $1;
            $result = $value;
        }

        return $result;

    }
}

sub get_registry_initscript_name
{
    my ($subsystem_type) = @_;
    my ($pki_initscript);

    if ($subsystem_type eq $CA) {
        $pki_initscript = $CA_INITSCRIPT;
    } elsif($subsystem_type eq $KRA) {
        $pki_initscript = $KRA_INITSCRIPT;
    } elsif($subsystem_type eq $OCSP) {
        $pki_initscript = $OCSP_INITSCRIPT;
    } elsif($subsystem_type eq $RA) {
        $pki_initscript = $RA_INITSCRIPT;
    } elsif($subsystem_type eq $TKS) {
        $pki_initscript = $TKS_INITSCRIPT;
    } elsif($subsystem_type eq $TPS) {
        $pki_initscript = $TPS_INITSCRIPT;
    } else {
        die "unknown subsystem type \"$subsystem_type\"";
    }

}

#######################################
# Generic selinux routines
#######################################

sub check_selinux_port
{
    my ($setype, $seport) = @_;

    return $SELINUX_PORT_UNDEFINED if $dry_run;

    if (defined $selinux_ports{$seport}) {
        if ($selinux_ports{$seport} eq $setype) {
            return $SELINUX_PORT_DEFINED;
        } elsif ($selinux_ports{$seport} eq "unreserved_port_t") {
            return $SELINUX_PORT_UNDEFINED;
        } else {
            return $SELINUX_PORT_WRONGLY_DEFINED;
        }
    } else {
        return $SELINUX_PORT_UNDEFINED;
    }
}

sub parse_selinux_ports
{
    open SM, '/usr/sbin/semanage port -l |grep tcp |sed \'s/tcp/___/g\'|sed \'s/\s//g\'|';
    while (<SM>) {
         chomp($_);
         my ($type, $portstr) = split /___/, $_;
         my @ports = split /,/, $portstr;
         foreach my $port (@ports) {
            if ($port =~ /(.*)-(.*)/) {
                for (my $count = $1; $count <= $2; $count++) {
                   $selinux_ports{$count} =  $type;
                }
            } else {
                $selinux_ports{$port} = $type;
            }
         }
    }
    close(SM);
}

sub add_selinux_port
{
    my ($setype, $seport, $cmds_ref) = @_;
    my $status = check_selinux_port($setype, $seport);

    if ($status == $SELINUX_PORT_UNDEFINED) {
        if ($cmds_ref) {
            $$cmds_ref .= "port -a -t $setype -p tcp $seport\n";
        } else {
            my $cmd = "$semanage port -a -t $setype -p tcp $seport\n";
            if (! run_command($cmd)) {
                emit("Failed to set selinux context for $seport", "error");
            }
        }

    } elsif ($status == $SELINUX_PORT_WRONGLY_DEFINED) {
        emit("Failed setting selinux context $setype for $seport.  " .
             "Port already defined otherwise.\n", "error");
    }
}

sub add_selinux_file_context
{
   my ($fcontext, $fname, $ftype, $cmds_ref) = @_;
   my ($result);

   emit(sprintf("add_selinux_file_context(%s)\n", join(", ", @_)), "debug");

   #check if fcontext has already been set
   my $tmp = `$semanage fcontext -l -n |grep $fname |grep ":$fcontext:" | wc -l`;
   chomp $tmp;
   if ($tmp ne "0") {
      emit("selinux fcontext for $fname already defined\n", "debug");
      return;
   }

   if ($ftype eq "f") {
       $$cmds_ref .= "fcontext -a -t $fcontext -f -- $fname\n";
   } else {
       $$cmds_ref .= "fcontext -a -t $fcontext $fname\n";
   }
}

1;
