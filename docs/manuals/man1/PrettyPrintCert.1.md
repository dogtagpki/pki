# PrettyPrintCert 1 "July 20, 2016" PKI "PKI Certificate Print Tool"

## NAME

PrettyPrintCert - print the contents of a certificate stored
as ASCII base-64 encoded data to a readable format.

## SYNOPSIS

**PrettyPrintCert** [**-simpleinfo**] *input-file* [*output-file*]

## DESCRIPTION

The **PrettyPrintCert** command provides a command-line utility
used to print the contents of a certificate stored as ASCII base-64 encoded data to a readable format.
The output of this command is displayed to standard output,
but can be optionally saved into a specified file.
An additional non-mandatory option is available
which limits the certificate information output of this command for easier parsing.

## OPTIONS

**-simpleinfo**  
    Optional. Prints limited certificate information in an easy to parse format;
    if this option is not specified, the entire contents of the certificate will be printed.

**&lt;input-file&gt;**  
    Mandatory. Specifies the path to the file containing the ASCII base-64 encoded certificate.

**&lt;output-file&gt;**  
    Optional. Specifies the path to the file in which the tool should write the certificate.
    If this option is not specified, the certificate information is written to the standard output.

## EXAMPLES

The following example converts the ASCII base-64 encoded certificate in the ascii_data.cert file
and writes the certificate in the pretty-print form to the output file cert.out:

```
$ PrettyPrintCert ascii_data.cert cert.out
```

For this example, the base-64 encoded certificate data in the ascii_data.cert looks like the following:

```
-----BEGIN CERTIFICATE-----
MIIECjCCAvKgAwIBAgIBCTANBgkqhkiG9w0BAQsFADBOMSswKQYDVQQKDCJ1c2Vy
c3lzLnJlZGhhdC5jb20gU2VjdXJpdHkgRG9tYWluMR8wHQYDVQQDDBZDQSBTaWdu
aW5nIENlcnRpZmljYXRlMB4XDTE2MDcyMjIwMzEzOFoXDTE3MDExODIxMzEzOFow
gZwxCzAJBgNVBAYTAlVTMRwwGgYDVQQKDBNFeGFtcGxlIENvcnBvcmF0aW9uMQsw
CQYDVQQLDAJJUzEpMCcGA1UEAwwgUHJldHR5UHJpbnRDZXJ0IFRlc3QgQ2VydGlm
aWNhdGUxIDAeBgkqhkiG9w0BCQEWEWFkbWluQGV4YW1wbGUuY29tMRUwEwYKCZIm
iZPyLGQBAQwFYWRtaW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDn
Jv8ADWpC7C3Bzb13n9zQwaDW8YfyshZd7lXI0cghJOSfRLT6C10LOi1yhI+7W3NN
MgYeLDCiRmKfHnqq6lpPg9aZmrxBwrn+30OdP+m1K6Crf6X9wqAWSR/r2hG4NuYi
ovcJg7ani5h4BL+V0hbUvfEs4o7QfOWjQZcoo2KbOKmRrodAA21XVjWGB1ELQLNN
hGwmZ6l1rtnN04Ruoclu8LaKMAAzFSH8cHEBtdCgxeDNy+bNnXbjO1wdruFNrars
W6wdc230AvHRcEUWEvQVq86vHfS4UZ5q0N1ychibrHZXB0/+TUtyKDQGx0K7ELSB
xgwt9QxEjKlXHiStcGupAgMBAAGjgaMwgaAwHwYDVR0jBBgwFoAUuzaYXWXLiOCH
IzdvW/evi4rrurUwTgYIKwYBBQUHAQEEQjBAMD4GCCsGAQUFBzABhjJodHRwOi8v
cGtpLWRlc2t0b3AudXNlcnN5cy5yZWRoYXQuY29tOjgwODAvY2Evb2NzcDAOBgNV
HQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqG
SIb3DQEBCwUAA4IBAQCgQ/vTCyQ+lHKNDNCtvbul2l6V3Sjzvj0il9t4HtorxoBF
3FIE6VNpUYFq0AkNS/LjV7ek7LRl8kuuiKaNpqF6RvAIPrABPDh7hE1Gi3Vm+Xw/
ndodT1AVII3x6xUbRsHu2iUVdZM5xO9ZFwA18nJUznL9q8lEGjj8vVCyFZuplUL+
pdKqL3SgBNUdyfiV6vywevI9jFoZBlsQbn4EjBs2nNeaFSZhZ1NG6tktSt85fJ51
IAiZv9Ipq0deHxFgpEywPq9lSrMZnm178PFlzRQUySHSm1pA+ngTydUKqZqAU0vr
XIDTmj4lE93VPZspnPS94p/0OT4Pe3NKAe+IbIv/
-----END CERTIFICATE-----
```

The certificate in pretty-print format in the cert.out file looks like the following:

```
    Certificate:
        Data:
            Version:  v3
            Serial Number: 0x9
            Signature Algorithm: SHA256withRSA - 1.2.840.113549.1.1.11
            Issuer: CN=CA Signing Certificate,O=example.com Security Domain
            Validity:
                Not Before: Friday, July 22, 2016 2:31:38 PM MDT America/Denver
                Not  After: Wednesday, January 18, 2017 2:31:38 PM MST America/Denver
            Subject: UID=admin,E=admin@example.com,CN=PrettyPrintCert Test Certificate,OU=IS,O=Example Corporation,C=US
            Subject Public Key Info:
                Algorithm: RSA - 1.2.840.113549.1.1.1
                Public Key:
                    Exponent: 65537
                    Public Key Modulus: (2048 bits) :
                        E7:26:FF:00:0D:6A:42:EC:2D:C1:CD:BD:77:9F:DC:D0:
                        C1:A0:D6:F1:87:F2:B2:16:5D:EE:55:C8:D1:C8:21:24:
                        E4:9F:44:B4:FA:0B:5D:0B:3A:2D:72:84:8F:BB:5B:73:
                        4D:32:06:1E:2C:30:A2:46:62:9F:1E:7A:AA:EA:5A:4F:
                        83:D6:99:9A:BC:41:C2:B9:FE:DF:43:9D:3F:E9:B5:2B:
                        A0:AB:7F:A5:FD:C2:A0:16:49:1F:EB:DA:11:B8:36:E6:
                        22:A2:F7:09:83:B6:A7:8B:98:78:04:BF:95:D2:16:D4:
                        BD:F1:2C:E2:8E:D0:7C:E5:A3:41:97:28:A3:62:9B:38:
                        A9:91:AE:87:40:03:6D:57:56:35:86:07:51:0B:40:B3:
                        4D:84:6C:26:67:A9:75:AE:D9:CD:D3:84:6E:A1:C9:6E:
                        F0:B6:8A:30:00:33:15:21:FC:70:71:01:B5:D0:A0:C5:
                        E0:CD:CB:E6:CD:9D:76:E3:3B:5C:1D:AE:E1:4D:AD:AA:
                        EC:5B:AC:1D:73:6D:F4:02:F1:D1:70:45:16:12:F4:15:
                        AB:CE:AF:1D:F4:B8:51:9E:6A:D0:DD:72:72:18:9B:AC:
                        76:57:07:4F:FE:4D:4B:72:28:34:06:C7:42:BB:10:B4:
                        81:C6:0C:2D:F5:0C:44:8C:A9:57:1E:24:AD:70:6B:A9
            Extensions:
                Identifier: Authority Key Identifier - 2.5.29.35
                    Critical: no
                    Key Identifier:
                        BB:36:98:5D:65:CB:88:E0:87:23:37:6F:5B:F7:AF:8B:
                        8A:EB:BA:B5
                Identifier: 1.3.6.1.5.5.7.1.1
                    Critical: no
                    Value:
                        30:40:30:3E:06:08:2B:06:01:05:05:07:30:01:86:32:
                        68:74:74:70:3A:2F:2F:70:6B:69:2D:64:65:73:6B:74:
                        6F:70:2E:75:73:65:72:73:79:73:2E:72:65:64:68:61:
                        74:2E:63:6F:6D:3A:38:30:38:30:2F:63:61:2F:6F:63:
                        73:70
                Identifier: Key Usage: - 2.5.29.15
                    Critical: yes
                    Key Usage:
                        Digital Signature
                        Non Repudiation
                        Key Encipherment
                Identifier: Extended Key Usage: - 2.5.29.37
                    Critical: no
                    Extended Key Usage:
                        1.3.6.1.5.5.7.3.2
                        1.3.6.1.5.5.7.3.4
        Signature:
            Algorithm: SHA256withRSA - 1.2.840.113549.1.1.11
            Signature:
                A0:43:FB:D3:0B:24:3E:94:72:8D:0C:D0:AD:BD:BB:A5:
                DA:5E:95:DD:28:F3:BE:3D:22:97:DB:78:1E:DA:2B:C6:
                80:45:DC:52:04:E9:53:69:51:81:6A:D0:09:0D:4B:F2:
                E3:57:B7:A4:EC:B4:65:F2:4B:AE:88:A6:8D:A6:A1:7A:
                46:F0:08:3E:B0:01:3C:38:7B:84:4D:46:8B:75:66:F9:
                7C:3F:9D:DA:1D:4F:50:15:20:8D:F1:EB:15:1B:46:C1:
                EE:DA:25:15:75:93:39:C4:EF:59:17:00:35:F2:72:54:
                CE:72:FD:AB:C9:44:1A:38:FC:BD:50:B2:15:9B:A9:95:
                42:FE:A5:D2:AA:2F:74:A0:04:D5:1D:C9:F8:95:EA:FC:
                B0:7A:F2:3D:8C:5A:19:06:5B:10:6E:7E:04:8C:1B:36:
                9C:D7:9A:15:26:61:67:53:46:EA:D9:2D:4A:DF:39:7C:
                9E:75:20:08:99:BF:D2:29:AB:47:5E:1F:11:60:A4:4C:
                B0:3E:AF:65:4A:B3:19:9E:6D:7B:F0:F1:65:CD:14:14:
                C9:21:D2:9B:5A:40:FA:78:13:C9:D5:0A:A9:9A:80:53:
                4B:EB:5C:80:D3:9A:3E:25:13:DD:D5:3D:9B:29:9C:F4:
                BD:E2:9F:F4:39:3E:0F:7B:73:4A:01:EF:88:6C:8B:FF
        FingerPrint
            MD2:
                EC:AE:A5:A3:E5:FA:30:3B:34:0E:FD:9D:ED:46:56:03
            MD5:
                CB:E1:80:0C:B3:66:DF:CF:3A:2B:A9:C1:F4:88:88:23
            SHA-1:
                B6:BA:84:0D:AE:4E:B0:CD:84:71:D8:A4:61:60:A7:2D:
                3A:7C:55:46
            SHA-256:
                B2:95:9C:8C:B9:3C:7B:9F:FF:8E:BD:92:90:BC:75:F5:
                BB:0D:96:2C:93:05:20:1B:4C:9D:B9:59:6F:54:25:5B
            SHA-512:
                B9:7A:1E:2E:59:8C:6F:76:F5:52:36:AD:A6:62:E9:DD:
                00:6E:82:7A:BA:38:1E:29:FC:F8:80:F1:DD:7C:81:92:
                F1:C2:E3:34:27:1A:7A:EB:95:36:DB:65:41:A2:46:19:
                FB:14:89:00:B5:8B:DB:AA:33:41:8C:6C:C4:75:CF:17
```

The following example command takes the same ASCII base-64 encoded certificate
in the ascii_data.cert file and writes the information contained within the certificate
to the simple format output file cert.simple:

```
$ PrettyPrintCert -simpleinfo ascii_data.cert cert.simple
```

The simple certificate information in the cert.simple output file looks like the following:

```
UID=admin
E=admin@example.com
CN=PrettyPrintCert Test Certificate
OU=IS
O=Example Corporation
C=US
```

## SEE ALSO

**PrettyPrintCrl(1)**, **pki(1)**

## AUTHORS

Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
