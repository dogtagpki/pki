# PrettyPrintCrl 1 "July 20, 2016" PKI "PKI CRL Print Tool"

## NAME

PrettyPrintCrl - reads a certificate revocation list (CRL) stored in an ASCII base-64 encoded file
and outputs it in a readable format.

## SYNOPSIS

**PrettyPrintCrl** *input-file* [*output-file*]

## DESCRIPTION

The **PrettyPrintCrl** command provides a command-line utility used to print the contents of a CRL
stored as ASCII base-64 encoded data in a file to a readable format.
The output of this command is displayed to standard output,
but can be optionally saved into a specified file.

## OPTIONS

**&lt;input-file&gt;**  
    Mandatory. Specifies the path to the file that contains the ASCII base-64 encoded CRL.

**&lt;output-file&gt;**  
    Optional. Specifies the path to the file to write the CRL.
    If the output file is not specified, the CRL information is written to the standard output.

## EXAMPLES

The following example **PrettyPrintCrl** command takes the ASCII base-64 encoded CRL
in the ascii_data.crl file and writes the CRL in the pretty-print format
to the output file crl.out:

```
$ PrettyPrintCrl ascii_data.crl crl.out
```

For this example, the base-64 encoded CRL data in the ascii_data.crl looks like the following:

```
-----BEGIN X509 CRL-----
MIICVDCCATwCAQEwDQYJKoZIhvcNAQELBQAwTjErMCkGA1UECgwidXNlcnN5cy5y
ZWRoYXQuY29tIFNlY3VyaXR5IERvbWFpbjEfMB0GA1UEAwwWQ0EgU2lnbmluZyBD
ZXJ0aWZpY2F0ZRcNMTYwNzIyMjExMjUwWhcNMTYwNzIyMjMwMDAwWjCBiDAgAgEK
Fw0xNjA3MjIyMDU1MTZaMAwwCgYDVR0VBAMKAQYwIAIBCRcNMTYwNzIyMjEwMTU2
WjAMMAoGA1UdFQQDCgEGMCACAQgXDTE2MDcyMjIxMTIyNVowDDAKBgNVHRUEAwoB
ATAgAgEHFw0xNjA3MjIyMTAxNTZaMAwwCgYDVR0VBAMKAQagLzAtMB8GA1UdIwQY
MBaAFLs2mF1ly4jghyM3b1v3r4uK67q1MAoGA1UdFAQDAgEKMA0GCSqGSIb3DQEB
CwUAA4IBAQCjnwpdLVU4sg3GnOFQiHpBuWspevzj0poHQs9b4Uv17o0MC4irftkR
zRBVgwLvdSd5WFEUSbhWVjhS4o4w84BXdmti/+UBS+mOVNxiKqs3Z7Fxcg+mCsiH
SDWT3iiqZVqlPMOKDzIQGj4XeArSBK13qjNdwKzVJZlXYfwzdDtyVKBJcoETXGZ3
irU8RTXo7OhO6xKDAaHjzVVynjfGdIDaavl1fjwXFufwZBeiXm1zyyFSvDUdny4G
29NTmM2945jCESeR7DV2q1LHG/v2rzCOKTWdPdXTPCics05KzUA4S6X+mp051wkh
yJM2LYpV6lKV6JiczHLrgf5QcqfwSkTX
-----END X509 CRL-----
```

The CRL in pretty-print format in the crl.out file looks like the following:

```
    Certificate Revocation List:
        Data:
            Version:  v2
            Signature Algorithm: SHA256withRSA - 1.2.840.113549.1.1.11
            Issuer: CN=CA Signing Certificate,O=example.com Security Domain
            This Update: Friday, July 22, 2016 3:12:50 PM MDT America/Denver
            Next Update: Friday, July 22, 2016 5:00:00 PM MDT America/Denver
            Revoked Certificates:
                Serial Number: 0xA
                Revocation Date: Friday, July 22, 2016 2:55:16 PM MDT America/Denver
                Extensions:
                    Identifier: Revocation Reason - 2.5.29.21
                        Critical: no
                        Reason: CA_Compromise
                Serial Number: 0x9
                Revocation Date: Friday, July 22, 2016 3:01:56 PM MDT America/Denver
                Extensions:
                    Identifier: Revocation Reason - 2.5.29.21
                        Critical: no
                        Reason: Affiliation_Changed
                Serial Number: 0x8
                Revocation Date: Friday, July 22, 2016 3:12:25 PM MDT America/Denver
                Extensions:
                    Identifier: Revocation Reason - 2.5.29.21
                        Critical: no
                        Reason: Key_Compromise
                Serial Number: 0x7
                Revocation Date: Friday, July 22, 2016 3:01:56 PM MDT America/Denver
                Extensions:
                    Identifier: Revocation Reason - 2.5.29.21
                        Critical: no
                        Reason: Certificate_Hold
        Extensions:
            Identifier: Authority Key Identifier - 2.5.29.35
                Critical: no
                Key Identifier:
                    BB:36:98:5D:65:CB:88:E0:87:23:37:6F:5B:F7:AF:8B:
                    8A:EB:BA:B5
            Identifier: CRL Number - 2.5.29.20
                Critical: no
                Number: 10
        Signature:
            Algorithm: SHA256withRSA - 1.2.840.113549.1.1.11
            Signature:
                A3:9F:0A:5D:2D:55:38:B2:0D:C6:9C:E1:50:88:7A:41:
                B9:6B:29:7A:FC:E3:D2:9A:07:42:CF:5B:E1:4B:F5:EE:
                8D:0C:0B:88:AB:7E:D9:11:CD:10:55:83:02:EF:75:27:
                79:58:51:14:49:B8:56:56:38:52:E2:8E:30:F3:80:57:
                76:6B:62:FF:E5:01:4B:E9:8E:54:DC:62:2A:AB:37:67:
                B1:71:72:0F:A6:0A:C8:87:48:35:93:DE:28:AA:65:5A:
                A5:3C:C3:8A:0F:32:10:1A:3E:17:78:0A:D2:04:AD:77:
                AA:33:5D:C0:AC:D5:25:99:57:61:FC:33:74:3B:72:54:
                A0:49:72:81:13:5C:66:77:8A:B5:3C:45:35:E8:EC:E8:
                4E:EB:12:83:01:A1:E3:CD:55:72:9E:37:C6:74:80:DA:
                6A:F9:75:7E:3C:17:16:E7:F0:64:17:A2:5E:6D:73:CB:
                21:52:BC:35:1D:9F:2E:06:DB:D3:53:98:CD:BD:E3:98:
                C2:11:27:91:EC:35:76:AB:52:C7:1B:FB:F6:AF:30:8E:
                29:35:9D:3D:D5:D3:3C:28:9C:B3:4E:4A:CD:40:38:4B:
                A5:FE:9A:9D:39:D7:09:21:C8:93:36:2D:8A:55:EA:52:
                95:E8:98:9C:CC:72:EB:81:FE:50:72:A7:F0:4A:44:D7
```

## SEE ALSO

**PrettyPrintCert(1)**, **pki(1)**

## AUTHORS

Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
