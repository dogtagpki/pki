# pkidestroy 8 "December 13, 2012" PKI "PKI Instance Removal Utility"

## NAME

pkidestroy - Removes a subsystem from an instance of PKI server.

## SYNOPSIS

**pkidestroy** **-s** *subsystem* **-i** *instance* [**-u** *security_domain_username*] [**-W** *security_domain_password_file*] [**-h**] [**-v**]

## DESCRIPTION

Removes a subsystem from an instance of PKI server.
This utility removes any of the PKI subsystems (CA, KRA, OCSP, TKS, and TPS).

An instance can contain multiple subsystems, although it may contain at most one of each type of subsystem.
So, for example, an instance could contain CA and KRA subsystems,  but not two CA subsystems.
If **pkidestroy** is invoked on the last subsystem in the instance, then that instance is removed.
Typically, as subsystems need to contact the CA to update the security domain, the CA instance should be the last instance to be removed.

## OPTIONS

**-s** *subsystem*  
    Specifies the subsystem to be removed, where *subsystem* is CA, KRA, OCSP, TKS, or TPS.
    If this option is not specified, **pkidestroy** will prompt for its value.

**-i** *instance*  
    Specifies the name of the instance from which the subsystem should be removed.
    The instance is located at /var/log/pki/*instance*.
    If this option is not specified, **pkidestroy** will prompt for its value.

**-u** *security_domain_username*   
    Specifies the username of the security domain of the subsystem.
    This is an **optional** parameter.

**-W** *security_domain_password_file*  
    Specifies the file containing the password of the security domain of the subsystem.
    This is an **optional** parameter.

**-h**, **--help**  
    Prints additional help information.

**-v**  
    Displays verbose information about the installation.
    This flag can be provided multiple times to increase verbosity.
    See **pkidestroy -h** for details.

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;.

## SEE ALSO

**pkispawn(8)**

## COPYRIGHT

Copyright (c) 2012 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
