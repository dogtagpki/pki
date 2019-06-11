# KRATool 1 "July 18, 2016" PKI "PKI Key Recovery Authority (KRA) Tool"

## NAME

KRATool - Command-Line utility used to export private keys from one or more KRA instances (generally legacy)
into a KRA instance (generally modern);
during the process of moving the keys, the KRATool can rewrap keys, renumber keys, or both.

## SYNOPSIS

The syntax for rewrapping keys:

**KRATool** **-kratool_config_file** *tool_config_file*  
	**-source_ldif_file** *original_ldif_file*  
	**-target_ldif_file** *newinstance_ldif_file*  
	**-log_file** *tool_log_file*  
	[**-source_pki_security_database_path** *nss_database*  
	**-source_storage_token_name** *token*  
	**-source_storage_certificate_nickname** *storage_certificate_nickname*  
	**-target_storage_certificate_file** *new_ASCII_storage_cert*  
	[**-source_pki_security_database_pwdfile** *password_file*]]  
	[**-source_kra_naming_context** *name* **-target_kra_naming_context** *name*]  
	[**-process_requests_and_key_records_only**]

The syntax for renumbering keys:

**KRATool** **-kratool_config_file** *tool_config_file*  
	**-source_ldif_file** *original_ldif_file*  
	**-target_ldif_file** *newinstance_ldif_file*  
	**-log_file** *tool_log_file*  
	[**-append_id_offset** *prefix_to_add* | **-remove_id_offset** *prefix_to_remove*]  
	[**-source_kra_naming_context** *name* **-target_kra_naming_context** *name*]  
	[**-process_requests_and_key_records_only**]

## DESCRIPTION

The **KRATool** command provides a command-line utility used to rewrap keys, renumber keys, or both.
For example, some private keys (mainly in older deployments) were wrapped in SHA-1, 1024-bit storage keys
when they were archived in the Key Recovery Authority (KRA).
These algorithms have become less secure as processor speeds improve and algorithms have been broken.
As a security measure, it is possible to rewrap the private keys in a new,
stronger storage key (SHA-256, 2048-bit keys).

**Note:**
Because the KRATool utility can export private keys from one KRA,
rewrap them with a new storage key, and then import them into a new KRA,
this tool can be used as part of a process of combining multiple KRA instances into a single KRA.

## OPTIONS

The following parameters are mandatory for both rewrapping and renumbering keys:

**-kratool_config_file** *tool_config_file*  
    Gives the complete path and filename of the configuration file used by the tool.
    This configuration process tells the tool how to process certain parameters in the existing key records,
    whether to apply any formatting changes (like changing the naming context or adding an offset)
    or even whether to update the modify date.
    The configuration file is required and a default file is included with the tool.
    The file format is described in the section entitled **Configuration File (.cfg)**.

**-source_ldif_file** *original_ldif_file*  
    Gives the complete path and filename of the LDAP Data Interchange Format (LDIF) file
    which contains all of the key data from the old KRA.

**-target_ldif_file** *newinstance_ldif_file*  
    Gives the complete path and filename of the LDIF file
    to which the tool will write all of the key data from the new KRA.
    This file is created by the tool as it runs.

**-log_file** *tool_log_file*  
    Gives the path and filename of the log file to use to log the tool progress and messages.
    This file is created by the tool as it runs.

The following parameters are optional for both rewrapping and renumbering keys:

**-source_kra_naming_context** *name*  
    Gives the naming context of the original KRA instance,
    the Distinguished Name (DN) element that refers to the original KRA.
    Key-related LDIF entries have a DN with the KRA instance name in it,
    such as cn=1,ou=kra,ou=requests,dc=alpha.example.com-pki-kra.
    The naming context for that entry is the DN value, alpha.example.com-pki-kra.
    These entries can be renamed, automatically, from the old KRA instance naming context
    to the new KRA instance naming context.  
    &nbsp;  
    While this argument is optional, it is recommended because it means that the LDIF file does not have to be edited
    before it is imported into the target KRA.
    If this argument is used, then the **-target_kra_naming_context** argument must also be used.

**-target_kra_naming_context** *name*  
    Gives the naming context of the new KRA instance, the name that the original key entries should be changed too.
    Key-related LDIF entries have a DN with the KRA instance name in it,
    such as cn=1,ou=kra,ou=requests,dc=omega.example.com-pki-kra.
    The naming context for that entry is the DN value, omega.example.com-pki-kra.
    These entries can be renamed, automatically, from the old KRA instance to the new KRA instance naming context.  
    &nbsp;  
    While this argument is optional, it is recommended because it means that the LDIF file does not have to be edited
    before it is imported into the target KRA.
    If this argument is used, then the **-source_kra_naming_context** argument must also be used.

**-process_requests_and_key_records_only**  
    Removes configuration entries from the source LDIF file, leaving only the key and request entries.  
    &nbsp;  
    While this argument is optional, it is recommended because it means that the LDIF file does not have to be edited
    before it is imported into the target KRA.

The following parameters are optional for rewrapping keys:

**-source_pki_security_database_path** *nss_databases*  
    Gives the full path to the directory which contains the Network Security Services (NSS) security databases
    used by the old KRA instance.  
    &nbsp;  
    This option is required if any other rewrap parameters are used.

**-source_storage_token_name** *token*  
    Gives the name of the token which stores the KRA data, like **Internal Key Storage Token** for internal tokens
    or a name like **NHSM6000-OCS** for the hardware token name.  
    &nbsp;  
    This option is required if any other rewrap parameters are used.

**-source_storage_certificate_nickname** *storage_certificate_nickname*  
    Gives the nickname of the KRA storage certificate for the old KRA instance.
    Either this certificate will be located in the security database for the old KRA instance
    or the security database will contain a pointer to the certificate in the hardware token.  
    &nbsp;  
    This option is required if any other rewrap parameters are used.

**-target_storage_certificate_file** *new_ASCII_storage_cert*  
    Gives the path and filename of an ASCII-formatted file of the storage certificate for the new KRA instance.
    The storage certificate should be exported from the new KRA's databases
    and stored in an accessible location before running KRATool.  
    &nbsp;  
    This option is required if any other rewrap parameters are used.

**-source_pki_security_database_pwdfile** *password_file*  
    Gives the path and filename to a password file that contains only the password for the storage token
    given in the **-source_storage_token_name** option.  
    &nbsp;  
    This argument is optional when other rewrap parameters are used.
    If this argument is not used, then the script prompts for the password.

The following parameters are optional for renumbering keys:

**-append_id_offset** *prefix_to_add*  
    Gives an ID number which will be preprended to every imported key, to prevent possible collisions.
    A unique ID offset should be used for every KRA instance which has keys exported using KRATool.  
    &nbsp;  
    If **-append_id_offset** is used, then do not use the **-remove_id_offset** option.

**-remove_id_offset** *prefix_to_remove*  
    Gives an ID number to remove from the beginning of every imported key.  
    &nbsp;  
    If **-remove_id_offset** is used, then do not use the **-append_id_offset** option.

## Configuration File (.cfg)

The required configuration file instructs the KRATool how to process attributes in the key archival
and key request entries in the LDIF file.
There are six types of entries:

* CA enrollment requests
* TPS enrollment requests
* CA key records
* TPS key records
* CA and TPS recovery requests (which are treated the same in the KRA)

Each key and key request has an LDAP entry with attributes that are specific to that kind of record.
For example, for a recovery request:

```
dn: cn=1,ou=kra,ou=requests,dc=alpha.example.com-pki-kra
objectClass: top
objectClass: request
objectClass: extensibleObject
requestId: 011
requestState: complete
dateOfCreate: 20110121181006Z
dateOfModify: 20110524094652Z
extdata-kra--005ftrans--005fdeskey: 3#C7#82#0F#5D#97GqY#0Aib#966#E5B#F56#F24n#
 F#9E#98#B3
extdata-public--005fkey: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDu6E3uG+Ep27bF1
 yTWvwIDAQAB
extdata-archive: true
extdata-requesttype: netkeyKeygen
extdata-iv--005fs: %F2%67%45%96%41%D7%FF%10
extdata-requestversion: 8.1.0
extdata-requestortype: NETKEY_RA
extdata-keyrecord: 1
extdata-wrappeduserprivate: %94%C1%36%D3%EA%4E%36%B5%42%91%AB%47%34%C0%35%A3%6
 F%E8%10%A9%B1%25%F4%BE%9C%11%D1%B3%3D%90%AB%79
extdata-userid: jmagne
extdata-keysize: 1024
extdata-updatedby: TPS-alpha.example.com-7889
extdata-dbstatus: UPDATED
extdata-cuid: 40906145C76224192D2B
extdata-requeststatus: complete
extdata-requestid: 1
extdata-result: 1
requestType: netkeyKeygen
cn: 1
creatorsName: cn=directory manager
modifiersName: cn=directory manager
createTimestamp: 20110122021010Z
modifyTimestamp: 20110122021010Z
nsUniqueId: b2891805-1dd111b2-a6d7e85f-2c2f0000
```

Much of that information passes through the script processing unchanged,
so it is entered into the new, target KRA just the same.
However, some of those attributes can and should be edited,
like the Common Name (CN) and DN being changed to match the new KRA instance.
The fields which can safely be changed are listed in the configuration file for each type of key entry.
(Any attribute not listed is not touched by the tool under any circumstances.)

If a field *should* be edited — meaning, the tool can update the record ID number or rename the entry —
then the value is set to true in the configuration file.
For example, this configuration updates the CN, DN, ID number, last modified date, and associated entry notes
for all CA enrollment requests:

```
kratool.ldif.caEnrollmentRequest.cn=true
kratool.ldif.caEnrollmentRequest.dateOfModify=true
kratool.ldif.caEnrollmentRequest.dn=true
kratool.ldif.caEnrollmentRequest.extdata.keyRecord=true
kratool.ldif.caEnrollmentRequest.extdata.requestNotes=true
kratool.ldif.caEnrollmentRequest.requestId=true
```

If a line is set to true, then the attribute is processed in the LDIF file.
By default, all possible attributes are processed.
Setting a line to false means that the KRATool skips that attribute and passes the value unchanged.
For example, this leaves the last modified time unchanged so that it doesn't update for when the KRATool runs:

```
kratool.ldif.caEnrollmentRequest.dateOfModify=false
```


**NOTE:**
Key enrollments, records, and requests all have an optional notes attribute
where administrators can enter notes about the process.
When the KRATool runs, it appends a note to that attribute
or adds the attribute with information about the tool running,
what operations were performed, and a timestamp:

```
extdata-requestnotes: [20110701150056Z]: REWRAPPED the 'existing DES3 symmetric 
session key' with the '2048-bit RSA public key' obtained from the target storage
 certificate + APPENDED ID offset '100000000000' + RENAMED source KRA naming con
text 'alpha.example.com-pki-kra' to target KRA naming context 'omega.example.com
-pki-kra' + PROCESSED requests and key records ONLY!
```

This information is very useful for both audit and maintenance of the KRA, so it is beneficial to keep the extdata.requestNotes parameter
for all of the key record types set to true.

**IMPORTANT:**
Every parameter line in the default **kratool.cfg** must be present in the **.cfg** file used when the tool is invoked.
No line can be omitted and every line must have a valid value (true or false).
If the file is not properly formatted, the KRATool will fail.

The formatting of the **.cfg** file is the same as the formatting used in the instance **CS.cfg** files.

A default **.cfg** file is included with the KRATool script.
This file (shown in the example entitled **Default kratool.cfg File**) can be copied and edited into a custom file
or edited directly and used with the tool.

### Default kratool.cfg File

```
kratool.ldif.caEnrollmentRequest._000=########################################
kratool.ldif.caEnrollmentRequest._001=##     KRA CA Enrollment Request      ##
kratool.ldif.caEnrollmentRequest._002=########################################
kratool.ldif.caEnrollmentRequest._003=##                                    ##
kratool.ldif.caEnrollmentRequest._004=##  NEVER allow 'KRATOOL' the ability ##
kratool.ldif.caEnrollmentRequest._005=##  to change the CA 'naming context' ##
kratool.ldif.caEnrollmentRequest._006=##  data in the following fields:     ##
kratool.ldif.caEnrollmentRequest._007=##                                    ##
kratool.ldif.caEnrollmentRequest._008=##    extdata-auth--005ftoken;uid     ##
kratool.ldif.caEnrollmentRequest._009=##    extdata-auth--005ftoken;userid  ##
kratool.ldif.caEnrollmentRequest._010=##    extdata-updatedby               ##
kratool.ldif.caEnrollmentRequest._011=##                                    ##
kratool.ldif.caEnrollmentRequest._012=##  NEVER allow 'KRATOOL' the ability ##
kratool.ldif.caEnrollmentRequest._013=##  to change CA 'numeric' data in    ##
kratool.ldif.caEnrollmentRequest._014=##  the following fields:             ##
kratool.ldif.caEnrollmentRequest._015=##                                    ##
kratool.ldif.caEnrollmentRequest._016=##    extdata-requestId               ##
kratool.ldif.caEnrollmentRequest._017=##                                    ##
kratool.ldif.caEnrollmentRequest._018=########################################
kratool.ldif.caEnrollmentRequest.cn=true
kratool.ldif.caEnrollmentRequest.dateOfModify=true
kratool.ldif.caEnrollmentRequest.dn=true
kratool.ldif.caEnrollmentRequest.extdata.keyRecord=true
kratool.ldif.caEnrollmentRequest.extdata.requestNotes=true
kratool.ldif.caEnrollmentRequest.requestId=true
kratool.ldif.caKeyRecord._000=#########################################
kratool.ldif.caKeyRecord._001=##          KRA CA Key Record          ##
kratool.ldif.caKeyRecord._002=#########################################
kratool.ldif.caKeyRecord._003=##                                     ##
kratool.ldif.caKeyRecord._004=##  NEVER allow 'KRATOOL' the ability  ##
kratool.ldif.caKeyRecord._005=##  to change the CA 'naming context'  ##
kratool.ldif.caKeyRecord._006=##  data in the following fields:      ##
kratool.ldif.caKeyRecord._007=##                                     ##
kratool.ldif.caKeyRecord._008=##    archivedBy                       ##
kratool.ldif.caKeyRecord._009=##                                     ##
kratool.ldif.caKeyRecord._010=#########################################
kratool.ldif.caKeyRecord.cn=true
kratool.ldif.caKeyRecord.dateOfModify=true
kratool.ldif.caKeyRecord.dn=true
kratool.ldif.caKeyRecord.privateKeyData=true
kratool.ldif.caKeyRecord.serialno=true
kratool.ldif.namingContext._000=############################################
kratool.ldif.namingContext._001=##       KRA Naming Context Fields        ##
kratool.ldif.namingContext._002=############################################
kratool.ldif.namingContext._003=##                                        ##
kratool.ldif.namingContext._004=##  NEVER allow 'KRATOOL' the ability to  ##
kratool.ldif.namingContext._005=##  change the CA 'naming context' data   ##
kratool.ldif.namingContext._006=##  in the following 'non-KeyRecord /     ##
kratool.ldif.namingContext._007=##  non-Request' fields (as these records ##
kratool.ldif.namingContext._008=##  should be removed via the option to   ##
kratool.ldif.namingContext._009=##  process requests and key records only ##
kratool.ldif.namingContext._010=##  if this is a KRA migration):          ##
kratool.ldif.namingContext._011=##                                        ##
kratool.ldif.namingContext._012=##    cn                                  ##
kratool.ldif.namingContext._013=##    sn                                  ##
kratool.ldif.namingContext._014=##    uid                                 ##
kratool.ldif.namingContext._015=##    uniqueMember                        ##
kratool.ldif.namingContext._016=##                                        ##
kratool.ldif.namingContext._017=##  NEVER allow 'KRATOOL' the ability to  ##
kratool.ldif.namingContext._018=##  change the KRA 'naming context' data  ##
kratool.ldif.namingContext._019=##  in the following 'non-KeyRecord /     ##
kratool.ldif.namingContext._020=##  non-Request' fields (as these records ##
kratool.ldif.namingContext._021=##  should be removed via the option to   ##
kratool.ldif.namingContext._022=##  process requests and key records only ##
kratool.ldif.namingContext._023=##  if this is a KRA migration):          ##
kratool.ldif.namingContext._024=##                                        ##
kratool.ldif.namingContext._025=##      dc                                ##
kratool.ldif.namingContext._026=##      dn                                ##
kratool.ldif.namingContext._027=##      uniqueMember                      ##
kratool.ldif.namingContext._028=##                                        ##
kratool.ldif.namingContext._029=##  NEVER allow 'KRATOOL' the ability to  ##
kratool.ldif.namingContext._030=##  change the TPS 'naming context' data  ##
kratool.ldif.namingContext._031=##  in the following 'non-KeyRecord /     ##
kratool.ldif.namingContext._032=##  non-Request' fields (as these records ##
kratool.ldif.namingContext._033=##  should be removed via the option to   ##
kratool.ldif.namingContext._034=##  process requests and key records only ##
kratool.ldif.namingContext._035=##  if this is a KRA migration):          ##
kratool.ldif.namingContext._036=##                                        ##
kratool.ldif.namingContext._037=##    uid                                 ##
kratool.ldif.namingContext._038=##    uniqueMember                        ##
kratool.ldif.namingContext._039=##                                        ##
kratool.ldif.namingContext._040=##  If '-source_naming_context            ##
kratool.ldif.namingContext._041=##  original source KRA naming context'   ##
kratool.ldif.namingContext._042=##  and '-target_naming_context           ##
kratool.ldif.namingContext._043=##  renamed target KRA naming context'    ##
kratool.ldif.namingContext._044=##  options are specified, ALWAYS         ##
kratool.ldif.namingContext._045=##  require 'KRATOOL' to change the       ##
kratool.ldif.namingContext._046=##  KRA 'naming context' data in ALL of   ##
kratool.ldif.namingContext._047=##  the following fields in EACH of the   ##
kratool.ldif.namingContext._048=##  following types of records:           ##
kratool.ldif.namingContext._049=##                                        ##
kratool.ldif.namingContext._050=##    caEnrollmentRequest:                ##
kratool.ldif.namingContext._051=##                                        ##
kratool.ldif.namingContext._052=##      dn                                ##
kratool.ldif.namingContext._053=##      extdata-auth--005ftoken;user      ##
kratool.ldif.namingContext._054=##      extdata-auth--005ftoken;userdn    ##
kratool.ldif.namingContext._055=##                                        ##
kratool.ldif.namingContext._056=##    caKeyRecord:                        ##
kratool.ldif.namingContext._057=##                                        ##
kratool.ldif.namingContext._058=##      dn                                ##
kratool.ldif.namingContext._059=##                                        ##
kratool.ldif.namingContext._060=##    recoveryRequest:                    ##
kratool.ldif.namingContext._061=##                                        ##
kratool.ldif.namingContext._062=##      dn                                ##
kratool.ldif.namingContext._063=##                                        ##
kratool.ldif.namingContext._064=##    tpsKeyRecord:                       ##
kratool.ldif.namingContext._065=##                                        ##
kratool.ldif.namingContext._066=##      dn                                ##
kratool.ldif.namingContext._067=##                                        ##
kratool.ldif.namingContext._068=##    tpsNetkeyKeygenRequest:             ##
kratool.ldif.namingContext._069=##                                        ##
kratool.ldif.namingContext._070=##      dn                                ##
kratool.ldif.namingContext._071=##                                        ##
kratool.ldif.namingContext._072=############################################
kratool.ldif.recoveryRequest._000=#####################################
kratool.ldif.recoveryRequest._001=##  KRA CA / TPS Recovery Request  ##
kratool.ldif.recoveryRequest._002=#####################################
kratool.ldif.recoveryRequest.cn=true
kratool.ldif.recoveryRequest.dateOfModify=true
kratool.ldif.recoveryRequest.dn=true
kratool.ldif.recoveryRequest.extdata.requestId=true
kratool.ldif.recoveryRequest.extdata.requestNotes=true
kratool.ldif.recoveryRequest.extdata.serialnumber=true
kratool.ldif.recoveryRequest.requestId=true
kratool.ldif.tpsKeyRecord._000=#########################################
kratool.ldif.tpsKeyRecord._001=##         KRA TPS Key Record          ##
kratool.ldif.tpsKeyRecord._002=#########################################
kratool.ldif.tpsKeyRecord._003=##                                     ##
kratool.ldif.tpsKeyRecord._004=##  NEVER allow 'KRATOOL' the ability  ##
kratool.ldif.tpsKeyRecord._005=##  to change the TPS 'naming context' ##
kratool.ldif.tpsKeyRecord._006=##  data in the following fields:      ##
kratool.ldif.tpsKeyRecord._007=##                                     ##
kratool.ldif.tpsKeyRecord._008=##    archivedBy                       ##
kratool.ldif.tpsKeyRecord._009=##                                     ##
kratool.ldif.tpsKeyRecord._010=#########################################
kratool.ldif.tpsKeyRecord.cn=true
kratool.ldif.tpsKeyRecord.dateOfModify=true
kratool.ldif.tpsKeyRecord.dn=true
kratool.ldif.tpsKeyRecord.privateKeyData=true
kratool.ldif.tpsKeyRecord.serialno=true
kratool.ldif.tpsNetkeyKeygenRequest._000=#####################################
kratool.ldif.tpsNetkeyKeygenRequest._001=##  KRA TPS Netkey Keygen Request  ##
kratool.ldif.tpsNetkeyKeygenRequest._002=#####################################
kratool.ldif.tpsNetkeyKeygenRequest._003=##                                 ##
kratool.ldif.tpsNetkeyKeygenRequest._004=##  NEVER allow 'KRATOOL' the      ##
kratool.ldif.tpsNetkeyKeygenRequest._005=##  ability to change the          ##
kratool.ldif.tpsNetkeyKeygenRequest._006=##  TPS 'naming context' data in   ##
kratool.ldif.tpsNetkeyKeygenRequest._007=##  the following fields:          ##
kratool.ldif.tpsNetkeyKeygenRequest._008=##                                 ##
kratool.ldif.tpsNetkeyKeygenRequest._009=##    extdata-updatedby            ##
kratool.ldif.tpsNetkeyKeygenRequest._010=##                                 ##
kratool.ldif.tpsNetkeyKeygenRequest._011=#####################################
kratool.ldif.tpsNetkeyKeygenRequest.cn=true
kratool.ldif.tpsNetkeyKeygenRequest.dateOfModify=true
kratool.ldif.tpsNetkeyKeygenRequest.dn=true
kratool.ldif.tpsNetkeyKeygenRequest.extdata.keyRecord=true
kratool.ldif.tpsNetkeyKeygenRequest.extdata.requestId=true
kratool.ldif.tpsNetkeyKeygenRequest.extdata.requestNotes=true
kratool.ldif.tpsNetkeyKeygenRequest.requestId=true
```

## EXAMPLES

The KRATool performs two operations: it can rewrap keys with a new private key,
and it can renumber attributes in the LDIF file entries for key records, including enrollments and recovery requests.
At least one operation (rewrap or renumber) must be performed and both can be performed in a single invocation.

### Rewrapping Keys

When rewrapping keys, the tool needs to be able to access the original NSS databases for the source KRA
and its storage certificate to unwrap the keys, as well as the storage certificate for the new KRA,
which is used to rewrap the keys.

```
$ KRATool -kratool_config_file KRATool.cfg \
    -source_ldif_file originalKRA.ldif \
    -target_ldif_file newKRA.ldif \
    -log_file kratool.log \
    -source_pki_security_database_path nssdb \
    -source_storage_token_name "Internal Key Storage Token" \
    -source_storage_certificate_nickname "storageCert cert-pki-kra" \
    -target_storage_certificate_file omega.crt
```

### Renumbering Keys

When multiple KRA instances are being merged into a single instance,
it is important to make sure that no key or request records have conflicting CNs, DNs, serial numbers, or request ID numbers.
These values can be processed to append a new, larger number to the existing values.

For the CN, the new number is the addition of the original CN plus the appended number.
For example, if the CN is 4 and the append number is 1000000, the new CN is 1000004.

For serial numbers and request IDs, the value is always a digit count plus the value.
So a CN of 4 has a serial number of 014, or one digit and the CN value.
If the append number is 1000000, the new serial number is 071000004,
for seven digits and then the sum of the append number (1000000) and the original value (4).

```
$ KRATool -kratool_config_file KRATool.cfg \
    -source_ldif_file originalKRA.ldif \
    -target_ldif_file newKRA.ldif \
    -log_file kratool.log \
    -append_id_offset 100000000000
```

### Restoring the Original Numbering

If a number has been appended to key entries, as in the example entitled **Renumbering Keys**, that number can also be removed.
Along with updating the CN, it also reconstructs any associated numbers, like serial numbers and request ID numbers.
Undoing a renumbering action may be necessary if the original number wasn't large enough to prevent conflicts
or as part of testing a migration or KRA consolidation process.

```
$ KRATool -kratool_config_file KRATool.cfg \
    -source_ldif_file originalKRA.ldif \
    -target_ldif_file newKRA.ldif \
    -log_file kratool.log \
    -remove_id_offset 100000000000
```

### Renumbering and Rewrapping in a Single Command

Rewrapping and renumbering operations can be performed in the same invocation.

```
$ KRATool -kratool_config_file KRATool.cfg \
    -source_ldif_file originalKRA.ldif \
    -target_ldif_file newKRA.ldif \
    -log_file kratool.log \
    -source_pki_security_database_path nssdb \
    -source_storage_token_name "Internal Key Storage Token" \
    -source_storage_certificate_nickname "storageCert cert-pki-kra" \
    -target_storage_certificate_file omega.crt \
    -append_id_offset 100000000000
```

## SEE ALSO

**pki(1)**

## AUTHORS

Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
