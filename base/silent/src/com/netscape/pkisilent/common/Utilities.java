package com.netscape.pkisilent.common;

// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;

import netscape.security.x509.CertificateSerialNumber;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.RDN;
import netscape.security.x509.SerialNumber;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.cmsutil.util.Utils;

public class Utilities {

    public Utilities() {// Do nothing
    }

    public String cleanupQuotes(String token) {

        StringBuffer buf = new StringBuffer();
        int length = token.length();
        int curIndex = 0;

        if (token.startsWith("\"") && token.endsWith("\"")) {
            curIndex = 1;
            length--;
        }

        boolean oneQuoteFound = false;
        boolean twoQuotesFound = false;

        while (curIndex < length) {
            char curChar = token.charAt(curIndex);

            if (curChar == '"') {
                twoQuotesFound = (oneQuoteFound) ? true : false;
                oneQuoteFound = true;
            } else {
                oneQuoteFound = false;
                twoQuotesFound = false;
            }

            if (twoQuotesFound) {
                twoQuotesFound = false;
                oneQuoteFound = false;
                curIndex++;
                continue;
            }

            buf.append(curChar);
            curIndex++;
        }

        return buf.toString();
    }

    public String removechar(String token) {

        StringBuffer buf = new StringBuffer();
        int end = token.length();
        int begin = 0;

        if (token.endsWith(";")) {
            end--;
        }

        while (begin < end) {
            char curChar = token.charAt(begin);

            buf.append(curChar);
            begin++;
        }
        return buf.toString();

    }

    public String parse_httpresponse(String line) {
        // look for name=value pair
        // remove trailing white spaces
        // remove trailing ;
        // remove double quotes

        String temp = line.substring(line.indexOf("=") + 1);

        return cleanupQuotes(removechar(temp.trim()));

    }

    public String remove_newline(String s) {
        if (s == null) {
            return null;
        }

        String val = "";

        for (int i = 0; i < s.length(); i++) {
            if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'n')) {
                i++;
                continue;
            } else if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'r')) {
                i++;
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            }
            val += s.charAt(i);
        }
        return val;

    }

    public String normalize(String s) {

        if (s == null) {
            return null;
        }

        String val = "";

        for (int i = 0; i < s.length(); i++) {
            if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'n')) {
                val += '\n';
                i++;
                continue;
            } else if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'r')) {
                i++;
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            }
            val += s.charAt(i);
        }
        return val;
    }

    /*
     * format of the file should be like this:
     * -----BEGIN CERTIFICATE-----
     * base64 encoded certificate
     * -----END CERTIFICATE-----
     */
    public String getcertfromfile(String filename) {
        StringBuffer tempBuffer = new StringBuffer();

        try {
            FileInputStream fis = new FileInputStream(filename);
            BufferedReader in = new BufferedReader(new InputStreamReader(fis));

            String temp;
            while ((temp = in.readLine()) != null) {

                if (temp.equalsIgnoreCase("-----BEGIN CERTIFICATE-----")
                        || temp.equalsIgnoreCase("-----END CERTIFICATE-----")) {
                    continue;
                }
                tempBuffer.append(temp);
            }

            return tempBuffer.toString();
        } catch (Exception e) {
            System.out.println("ERROR: getcertfromfile" + e.toString());
            return null;
        }

    }

    public String getcertfromfile_withheaders(String filename) {
        StringBuffer tempBuffer = new StringBuffer();

        try {
            FileInputStream fis = new FileInputStream(filename);
            BufferedReader in = new BufferedReader(new InputStreamReader(fis));

            String temp;
            while ((temp = in.readLine()) != null) {
                tempBuffer.append(temp);
            }
            return tempBuffer.toString();
        } catch (Exception e) {
            System.out.println(
                    "ERROR: getcertfromfile_withheaders" + e.toString());
            return null;
        }
    }

    /*
     * format of the file should be like this:
     * -----BEGIN CERTIFICATE REVOCATION LIST-----
     * base64 encoded CRL
     * -----END CERTIFICATE REVOCATION LIST-----
     */
    public String getcrlfromfile(String filename) {
        StringBuffer tempBuffer = new StringBuffer();

        try {
            FileInputStream fis = new FileInputStream(filename);
            BufferedReader in = new BufferedReader(new InputStreamReader(fis));

            String temp;
            while ((temp = in.readLine()) != null) {
                tempBuffer.append(temp);
            }

            return tempBuffer.toString();
        } catch (Exception e) {
            System.out.println("ERROR: getcrlfromfile" + e.toString());
            return null;
        }

    }

    /*
     * format of the file should be like this:
     * -----BEGIN CERTIFICATE-----
     * base64 encoded certificate
     * -----END CERTIFICATE-----
     */
    public String getcafromfile(String filename) {
        StringBuffer tempBuffer = new StringBuffer();

        try {
            FileInputStream fis = new FileInputStream(filename);
            BufferedReader in = new BufferedReader(new InputStreamReader(fis));

            String temp;
            while ((temp = in.readLine()) != null) {
                tempBuffer.append(temp);
            }

            return tempBuffer.toString();
        } catch (Exception e) {
            System.out.println("ERROR: getcafromfile" + e.toString());
            return null;
        }

    }

    /*
     * function for RFC 2254. converts a x509 certificate given as
     * a binary array[] to a Ldap filter string
     */
    public static String escapeBinaryData(byte data[]) {
        String result = "";

        for (int i = 0; i < data.length; i++) {
            String s = Integer.toHexString(0xff & data[i]);

            if (s.length() == 1) {
                s = "0" + s;
            }
            result = result + "\\" + s;
        }

        System.out.println("LDAP_FILTER=" + result);
        return result;
    }

    /*
     * function to decode base64 encoded certificate
     */
    public CertificateRecord decode_cert(String cert) {

        String head = "-----BEGIN CERTIFICATE-----";
        String tail = "-----END CERTIFICATE-----";

        CertificateRecord cr = new CertificateRecord();

        int head_pos = cert.indexOf(head);
        int tail_pos = cert.indexOf(tail);

        // String not found
        if (head_pos == -1 || tail_pos == -1) {
            return null;
        }

        String temp = cert.substring(head_pos + head.length(), tail_pos);

        temp = temp.replaceAll("\\r", "");
        temp = temp.replaceAll("\\n", "");

        try {
            // BASE64Decoder base64 = new BASE64Decoder();
            // byte decodedBASE64Cert[] = base64.decodeBuffer(temp);
            byte decodedBASE64Cert[] = Utils.base64decode(temp);
            X509CertImpl x509_cert = new X509CertImpl(decodedBASE64Cert);
            X509CertInfo certinfo = (X509CertInfo) x509_cert.get("x509.INFO");

            /* Get Serial Number */
            CertificateSerialNumber csn = (CertificateSerialNumber)
                    certinfo.get(X509CertInfo.SERIAL_NUMBER);
            SerialNumber sn = (SerialNumber) csn.get("NUMBER");

            // just adding serialnumber for add.
            // we can add mode here like subject name, extensions,issuer to this record.
            cr.serialNumber = sn.getNumber().toString().trim();

            /* Get Subject Name */

            CertificateSubjectName csn1 = (CertificateSubjectName)
                    certinfo.get(X509CertInfo.SUBJECT);

            X500Name dname = (X500Name) csn1.get(CertificateSubjectName.DN_NAME);

            String pp = "";
            RDN[] rdns = dname.getNames();

            for (int i = rdns.length - 1; i >= 0; i--) {
                pp = pp + rdns[i] + "\n";
            }

            cr.subject = pp;

        } catch (Exception e) {
            System.out.println("ERROR: Exception when decoding certificate=" + e);
            e.printStackTrace();
            return null;
        }

        return cr;

    }

}; // end class
