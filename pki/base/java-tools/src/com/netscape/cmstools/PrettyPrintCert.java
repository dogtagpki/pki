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
package com.netscape.cmstools;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.util.Locale;

import netscape.security.util.CertPrettyPrint;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.RDN;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

/**
 * The PrettyPrintCert class is a utility program designed to "pretty print"
 * a certificate. It assumes that the name of a data file is passed to the
 * program via the command line, and that the contents contain a certificate
 * encoded in an ASCII BASE 64 format. Note that the data file may contain
 * an optional "-----BEGIN" header and/or an optional "-----END" trailer.
 * 
 * <P>
 * The program may be invoked as follows:
 * 
 * <PRE>
 * 
 *      PrettyPrintCert &lt;input filename&gt; [output filename]
 * 
 *      NOTE:  &lt;input filename&gt;   must contain an ASCII
 *                                BASE 64 encoded certificate
 * 
 *             &lt;output filename&gt;  contains a certificate displayed
 *                                in a "pretty print" ASCII format
 * </PRE>
 * 
 * @version $Revision$, $Date$
 */

public class PrettyPrintCert {
    // Define constants
    public static final int ARGC = 2;
    public static final String HEADER = "-----BEGIN";
    public static final String TRAILER = "-----END";

    public static void usageAndExit() {
        System.out.println("Usage:  PrettyPrintCert " +
                "[options] " +
                "<input filename> " +
                "[output filename]");
        System.out.println("\n options: ");
        System.out.println("    -simpleinfo     :  prints limited cert info in easy to parse format");
        System.exit(0);
    }

    public static void main(String argv[]) {

        BufferedReader inputCert = null;
        String encodedBASE64CertChunk = new String();
        String encodedBASE64Cert = new String();
        byte decodedBASE64Cert[] = null;
        X509CertImpl cert = null;
        Locale aLocale = null;
        CertPrettyPrint certDetails = null;
        String pp = new String();
        FileOutputStream outputCert = null;
        boolean mSimpleInfo = false;
        String inputfile = null;
        String outputfile = null;

        // parse arguments

        for (int i = 0; i < argv.length; i++) {

            // deal with empty arguments passed in by script
            if (argv[i].equals("")) {
                continue;
            }

            // parse options
            if (argv[i].charAt(0) == '-') {
                if (argv[i].equals("-simpleinfo")) {
                    mSimpleInfo = true;
                    continue;
                } else {
                    System.out.println("Illegal option: " + argv[i]);
                    usageAndExit();
                }
            }

            // deal with filename

            if (inputfile == null) {
                inputfile = argv[i];
                continue;
            }

            if (outputfile == null) {
                outputfile = argv[i];
                continue;
            }

            System.out.println("Error - Too many arguments");
            System.exit(0);
        }

        if (inputfile == null) {
            usageAndExit();
        }

        // (2) Create a DataInputStream() object to the BASE 64
        //     encoded certificate contained within the file
        //     specified on the command line
        try {
            inputCert = new BufferedReader(new InputStreamReader(
                            new BufferedInputStream(
                                    new FileInputStream(
                                            inputfile))));
        } catch (FileNotFoundException e) {
            System.out.println("PrettyPrintCert:  can't find file " +
                    inputfile + ":\n" + e);
            return;
        }

        // (3) Read the entire contents of the specified BASE 64 encoded
        //     certificate into a String() object throwing away any
        //     headers beginning with HEADER and any trailers beginning
        //     with TRAILER
        try {
            while ((encodedBASE64CertChunk = inputCert.readLine()) != null) {
                if (!(encodedBASE64CertChunk.startsWith(HEADER)) &&
                        !(encodedBASE64CertChunk.startsWith(TRAILER))) {
                    encodedBASE64Cert += encodedBASE64CertChunk.trim();
                }
            }
        } catch (IOException e) {
            System.out.println("PrettyPrintCert:  Unexpected BASE64 " +
                    "encoded error encountered in readLine():\n" +
                    e);
        }

        // (4) Close the DataInputStream() object
        try {
            inputCert.close();
        } catch (IOException e) {
            System.out.println("PrettyPrintCert:  Unexpected BASE64 " +
                    "encoded error encountered in close():\n" + e);
        }

        // (5) Decode the ASCII BASE 64 certificate enclosed in the
        //     String() object into a BINARY BASE 64 byte[] object

        decodedBASE64Cert = com.netscape.osutil.OSUtil.AtoB(encodedBASE64Cert);

        // (6) Create an X509CertImpl() object from the BINARY BASE 64
        //     byte[] object
        try {
            cert = new X509CertImpl(decodedBASE64Cert);
        } catch (CertificateException e) {
            System.out.println("PrettyPrintCert:  Error encountered " +
                    "on parsing certificate :\n" + e);
        }

        if (mSimpleInfo) {
            try {
                X509CertInfo certinfo = (X509CertInfo) cert.get("x509.INFO");

                CertificateSubjectName csn = (CertificateSubjectName)
                        certinfo.get(X509CertInfo.SUBJECT);

                X500Name dname = (X500Name) csn.get(CertificateSubjectName.DN_NAME);

                pp = "";
                RDN[] rdns = dname.getNames();

                for (int i = rdns.length - 1; i >= 0; i--) {
                    pp = pp + rdns[i] + "\n";
                }

            } catch (Exception e) {
                System.out.println("ERROR");
                e.printStackTrace();
            }
        } else {
            // (7) For this utility, always specify the default Locale
            aLocale = Locale.getDefault();

            // (8) Create a CertPrettyPrint() object
            certDetails = new CertPrettyPrint(cert);

            // (9) Convert the CertPrettyPrint() object into a String() object
            pp = certDetails.toString(aLocale);
        }

        // (10) Finally, "pretty print" the actual certificate to the console
        //      unless an output file has been specified
        if (outputfile == null) {
            System.out.println(pp);
        } else {
            try {
                outputCert = new FileOutputStream(outputfile);
            } catch (Exception e) {
                System.out.println("PrettyPrintCert:  unable to open file " +
                        argv[1] + " for writing:\n" + e);
                return;
            }

            try {
                outputCert.write(pp.getBytes());
            } catch (IOException e) {
                System.out.println("PrettyPrintCert:  Unexpected error " +
                        "encountered while attempting to write() " +
                        outputfile + ":\n" + e);
            }

            try {
                outputCert.close();
            } catch (IOException e) {
                System.out.println("PrettyPrintCert:  Unexpected error " +
                        "encountered while attempting to close() " +
                        outputfile + ":\n" + e);
            }
        }
    }
}
