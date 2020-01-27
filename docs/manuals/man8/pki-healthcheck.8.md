# pki-healthcheck 8 "January 16, 2020" PKI "pki-healthcheck CLI"

## NAME

pki-healthcheck - Command-Line Interface to check health of a PKI installation

## SYNOPSIS

**pki-healthcheck** [*CLI-options*]

## DESCRIPTION

A PKI installation is a complex setup and identifying real or potential issues can be difficult and require a lot of analysis. This tool aims to reduce the burden by attempting to identify issues in advance so that they can be corrected, ideally before the issue becomes critical.

### ORGANIZATION

The areas of the system to check are logically grouped together. This grouping is called a source. A source consists of one or more checks.

A check is as atomic as possible to limit the scope and complexity and provide a yes/no answer on whether that particular configuration is correct.

Each check will return a result, either a result of WARNING, ERROR, CRITICAL or SUCCESS. Returning SUCCESS tells you that the check was done and was deemed correct. This should help track when the last time  something  was examined.

Upon  failure,  the  output  will include the source and check that detected the failure along with a message and name/value pairs indicating the problem. If a check can't make a final determination, it throws WARNING so that it can be examined.

## OPTIONS

### COMMANDS

**--list-sources**  
    Display a list of the available sources and the checks associated with those sources.

### OPTIONAL ARGUMENTS

**--source**=*SOURCE*  
    Execute one or more checks within this given source.

**--check**=*CHECK*  
    Execute this particular check within a source. A *source* must be supplied as well with this option.

**--output-type**=*TYPE*  
    Set the output type. Defaults to JSON.

**--failures-only**  
    Exclude SUCCESS results on output.

**--severity**=*SEVERITY*  
    Only report errors in the requested severity of SUCCESS, WARNING, ERROR or CRITICAL. This can be provided multiple times to search on multiple levels.

**--debug**  
    Generate additional debugging output.

### JSON OUTPUT

The output is displayed as a list of result messages for each check executed in JSON format. This could be input for a monitoring system.

**--output-file**=*FILENAME*  
    Write the output to this filename rather than stdout.

**--indent**=*INDENT*  
    Pretty-print the JSON with this indention level. This can make the output more human-readable.

### HUMAN-READABLE OUTPUT

The results are displayed in a more human-readable format.

**--input-file**=*FILENAME*  
    Take as input a JSON results output and convert it to a more human-readable form.

## EXIT STATUS

0 if all checks were successful

1 if any one check failed or the command failed to execute properly

## FILES

/etc/pki/healthcheck.conf

## NOTES

### CHECKS INCLUDED

**Certificate sync between CS.cfg and NSS database**  
Checks whether the system certificates in CS.cfg and NSS database are the same

## BUGS

**pki-healthcheck** tool can operate only on a *single instance* PKI installation with the instance name as *pki-tomcat*

## EXAMPLES

Execute healthcheck with the default JSON output:  
**pki-healthcheck**

Execute healthcheck with a prettier JSON output:  
**pki-healthcheck --indent 2**

Execute healthcheck and only display errors:  
**pki-healthcheck --failures-only**

Execute healthcheck and display results in human-readable format:  
**pki-healthcheck --output-format human**

Execute healthcheck and write results to a file:  
**pki-healthcheck --output-file /var/log/pki/healthcheck/results.json**

Display in the previous report in a human-readable format:  
**pki-healthcheck --output-format human --input-file /var/log/pki/healthcheck/results.json**

## AUTHORS

Dinesh Prasanth M K \<dmoluguw@redhat.com>

## COPYRIGHT

Copyright (c) 2020 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is  available  at <http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>.
