# tpsclient 1 "Jul 8, 2015" PKI "PKI TPS tpsclient test program"

# NAME

**tpsclient** - TPS testing tool to exercise TPS server functionality, simulating a smart card.

# SYNOPSIS

**tpsclient** < *script-file*  
**tpsclient**

Note this tool currently works to simulate Secure Channel Protocol 01, GP201 tokens.
Support for SCP02/GP211 is planned in future versions.

# DESCRIPTION

The **tpsclient** command provides a way to exercise the TPS server without a hardware token,
through the use of a simple script file containing commands to the **tpsclient** engine.

# OPTIONS

The only option is whether or not to provide a script file.
Not providing the script argument will launch the program in interactive mode, though this is not recommended.
The best way to interact with the TPS server is to provide a simple script file to **tpsclient**.

# OPERATIONS

The Operations are contained within the **tpsclient** script file. Some sample scripts are provided below.

# EXAMPLES

**tpsclient**

This command will simply run the program in interactive mode.
Commands will have to be issued manually with this mode one by one, and thus is not recommended.

List of commands inside interactive mode:

```
Output> Available Operations:
Output> op=debug filename=<filename> - enable debugging
Output> op=help
Output> op=ra_enroll uid=<uid> pwd=<pwd> num_threads=<number of threads> secureid_pin=<secureid_pin> keygen=<true|false> - Enrollment Via RA
Output> op=ra_reset_pin uid=<uid> pwd=<pwd> num_threads=<number of threads> secureid_pin=<secureid_pin> new_pin=<new_pin> - Reset Pin Via RA
Output> op=ra_update uid=<uid> pwd=<pwd> num_threads=<number of threads> secureid_pin=<secureid_pin> new_pin=<new_pin> - Reset Pin Via RA
Output> op=token_set <name>=<value> - Set Token Value
Output> op=token_status - Print Token Status
Output> op=var_get name=<name> - Get Value of Variable
Output> op=var_list - List All Variables
Output> op=var_set name=<name> value=<value> - Set Value to Variable
```


**tpsclient** < format.txt

**tpsclient** < enroll.txt

`format.txt` contents:

```
# Set the host name of the TPS server
op=var_set name=ra_host value=localhost.localdomain

# Set the port where the TPS server is listening
op=var_set name=ra_port value=8080

# Set the URL on the TPS that responds to client token operation requests
op=var_set name=ra_uri value=/tps/tps

# Set the cuid number of our virtual token and some other values needed by TPS
op=token_set cuid=40906145C76224192D2B msn=01020304 app_ver=6FBBC105 key_info=0101 major_ver=1 minor_ver=1

# Set the global platform auth key for the virtual token
op=token_set auth_key=404142434445464748494a4b4c4d4e4f

# Set the global platform mac key for the virtual token
op=token_set mac_key=404142434445464748494a4b4c4d4e4f

# Set the global platform kek key for the virtual token
op=token_set kek_key=404142434445464748494a4b4c4d4e4f

#Issue the actual request to format our token to the TPS server.
# Within this command we must provide the authentication userid, authentication password, and virtual token PIN value to proceed
# Also, the "extensions" consist of extra info evaluated by TPS. In this case we declare the "type" of our virtual token.
# The TPS uses the type to control the flow of the operation.

op=ra_format uid=user1 pwd=secret123 new_pin=secret123 num_threads=1  extensions=tokenType=userKey

# Exit the operation and leave the program

op=exit
```

`enroll.txt` contents:

```
# Set the host name of the TPS server
op=var_set name=ra_host value=localhost.localdomain

# Set the port where the TPS server is listening
op=var_set name=ra_port value=8080

# Set the URL on the TPS that responds to client token operation requests
op=var_set name=ra_uri value=/tps/tps

# Set the cuid number of our virtual token and some other values needed by TPS
op=token_set cuid=40906145C76224192D2B msn=01020304 app_ver=6FBBC105 key_info=0101 major_ver=1 minor_ver=1

# Set the global platform auth key for the virtual token
op=token_set auth_key=404142434445464748494a4b4c4d4e4f

# Set the global platform mac key for the virtual token
op=token_set mac_key=404142434445464748494a4b4c4d4e4f

# Set the global platform kek key for the virtual token
op=token_set kek_key=404142434445464748494a4b4c4d4e4f

#Issue the actual request to format our token to the TPS server.
# Within this command we must provide the authentication userid, authentication password, and virtual token PIN value to proceed
# Also, the "extensions" consist of extra info evaluated by TPS. In this case we declare the "type" of our virtual token.
# The TPS uses the type to control the flow of the operation.

op=ra_enroll uid=user1 pwd=secret123 new_pin=secret123 num_threads=1  extensions=tokenType=userKey
```

# COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
