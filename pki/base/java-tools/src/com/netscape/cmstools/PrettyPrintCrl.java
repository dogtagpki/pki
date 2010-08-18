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


import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import netscape.security.x509.*;
import netscape.security.util.*;


/**
 * The PrettyPrintCrl class is a utility program designed to "pretty print"
 * a CRL.  It assumes that the name of a data file is passed to the
 * program via the command line, and that the contents contain a CRL
 * encoded in an ASCII BASE 64 format.  Note that the data file may contain
 * an optional "-----BEGIN" header and/or an optional "-----END" trailer.
 *
 * <P>
 * The program may be invoked as follows:
 * <PRE>
 *
 *      PrettyPrintCrl <input filename> [output filename]
 *
 *      NOTE:  <input filename>   must contain an ASCII
 *                                BASE 64 encoded CRL
 *
 *             [output filename]  contains a CRL displayed
 *                                in a "pretty print" ASCII format
 * </PRE>
 *
 * @version $Revision$, $Date$
 */

public class PrettyPrintCrl {
    // Define constants
    public static final int    ARGC = 2;
    public static final String HEADER = "-----BEGIN";
    public static final String TRAILER = "-----END";

    public static void main(String argv[]) {

        BufferedReader inputCrl = null;
        String encodedBASE64CrlChunk = new String();
        String encodedBASE64Crl = new String();
        byte decodedBASE64Crl[] = null;
        X509CRLImpl crl = null;
        Locale aLocale = null;
        CrlPrettyPrint CrlDetails = null;
        String pp = new String();
        FileOutputStream outputCrl = null;

        // (1) Check that at least one argument was submitted to the program
        if ((argv.length < 1) || (argv.length > ARGC)) {
            System.out.println("Usage:  PrettyPrintCrl " +
                "<input filename> " +
                "[output filename]");
            return;
        }

        try {
            OIDMap.addAttribute(DeltaCRLIndicatorExtension.class.getName(),
                DeltaCRLIndicatorExtension.OID,
                DeltaCRLIndicatorExtension.NAME);
        } catch (CertificateException e) {
        }
        try {
            OIDMap.addAttribute(HoldInstructionExtension.class.getName(),
                HoldInstructionExtension.OID,
                HoldInstructionExtension.NAME);
        } catch (CertificateException e) {
        }
        try {
            OIDMap.addAttribute(InvalidityDateExtension.class.getName(),
                InvalidityDateExtension.OID,
                InvalidityDateExtension.NAME);
        } catch (CertificateException e) {
        }
        try {
            OIDMap.addAttribute(IssuingDistributionPointExtension.class.getName(),
                IssuingDistributionPointExtension.OID,
                IssuingDistributionPointExtension.NAME);
        } catch (CertificateException e) {
        }

        // (2) Create a DataInputStream() object to the BASE 64
        //     encoded CRL contained within the file
        //     specified on the command line
        try {
            inputCrl = new BufferedReader(new InputStreamReader(
                            new BufferedInputStream(
                                new FileInputStream(
                                    argv[0]))));
        } catch (FileNotFoundException e) {
            System.out.println("PrettyPrintCrl():  can''t find file " +
                argv[0] + ":\n" + e);
            return;
        }

        // (3) Read the entire contents of the specified BASE 64 encoded
        //     CRL into a String() object throwing away any
        //     headers beginning with HEADER and any trailers beginning
        //     with TRAILER
        try {
            while ((encodedBASE64CrlChunk = inputCrl.readLine()) != null) {
                if (!(encodedBASE64CrlChunk.startsWith(HEADER)) &&
                    !(encodedBASE64CrlChunk.startsWith(TRAILER))) {
                    encodedBASE64Crl += encodedBASE64CrlChunk.trim();
                }
            }
        } catch (IOException e) {
            System.out.println("PrettyPrintCrl():  Unexpected BASE64 " +
                "encoded error encountered in readLine():\n" +
                e);
        }

        // (4) Close the DataInputStream() object
        try {
            inputCrl.close();
        } catch (IOException e) {
            System.out.println("PrettyPrintCrl():  Unexpected BASE64 " +
                "encoded error encountered in close():\n" + e);
        }
		
        // (5) Decode the ASCII BASE 64 CRL enclosed in the
        //     String() object into a BINARY BASE 64 byte[] object

        decodedBASE64Crl = com.netscape.osutil.OSUtil.AtoB(encodedBASE64Crl);

        // (6) Create an X509CRLImpl() object from the BINARY BASE 64
        //     byte[] object
        try {
            crl = new X509CRLImpl(decodedBASE64Crl);
        } catch (CRLException e) {
            System.out.println("PrettyPrintCrl():  Error encountered " +
                "on parsing and initialization errors:\n" + e);
        } catch (X509ExtensionException e) {
            System.out.println("PrettyPrintCrl():  Error encountered " +
                "on parsing and initialization errors:\n" + e);
        }

        // (7) For this utility, always specify the default Locale
        aLocale = Locale.getDefault(); 

        // (8) Create a CrlPrettyPrint() object
        CrlDetails = new CrlPrettyPrint(crl);

        // (9) Convert the CrlPrettyPrint() object into a String() object
        pp = CrlDetails.toString(aLocale);

        // (10) Finally, "pretty print" the actual CRL to the console
        //      unless an output file has been specified
        if (argv.length != ARGC) {
            System.out.println(pp);
        } else {
            try {
                outputCrl = new FileOutputStream(argv[1]);
            } catch (IOException e) {
                System.out.println("PrettyPrintCrl():  unable to open file " +
                    argv[1] + " for writing:\n" + e);
                return;
            }

            try {
                outputCrl.write(pp.getBytes());
            } catch (IOException e) {
                System.out.println("PrettyPrintCrl():  I/O error " +
                    "encountered during write():\n" +
                    e);
            }

            try {
                outputCrl.close();
            } catch (IOException e) {
                System.out.println("PrettyPrintCrl():  Unexpected error " +
                    "encountered while attempting to close() " +
                    argv[1] + ":\n" + e);
            }
        }
    }
}

