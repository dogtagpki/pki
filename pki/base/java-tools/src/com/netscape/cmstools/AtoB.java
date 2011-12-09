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


/**
 * The AtoB class is a utility program designed to "translate" an ASCII
 * BASE 64 encoded blob into a BINARY BASE 64 encoded blob.  It assumes
 * that the name of a data file is passed to the program via the command line,
 * and that the contents contain a blob encoded in an ASCII BASE 64
 * format.  Note that the data file may contain an optional "-----BEGIN" header
 * and/or an optional "-----END" trailer.
 *
 * <P>
 * The program may be invoked as follows:
 * <PRE>
 *
 *      AtoB &lt;input filename&gt; &lt;output filename&gt;
 *
 *      NOTE:  &lt;input filename&gt;   must contain an ASCII
 *                                BASE 64 encoded blob
 *
 *             &lt;output filename&gt;  contains a BINARY
 *                                BASE 64 encoded blob
 * </PRE>
 *
 * @version $Revision$, $Date$
 */
public class AtoB {
    // Define constants
    public static final int    ARGC = 2;
    public static final String HEADER = "-----BEGIN";
    public static final String TRAILER = "-----END";

    public static void main(String argv[]) {

        BufferedReader inputBlob = null;
        String asciiBASE64BlobChunk = new String();
        String asciiBASE64Blob = new String();
        byte binaryBASE64Blob[] = null;
        FileOutputStream outputBlob = null;

        // (1) Check that two arguments were submitted to the program
        if (argv.length != ARGC) {
            System.out.println("Usage:  AtoB " +
                "<input filename> " +
                "<output filename>");
            return;
        }

        // (2) Create a DataInputStream() object to the BASE 64
        //     encoded blob contained within the file
        //     specified on the command line
        try {
            inputBlob = new BufferedReader(new InputStreamReader(
                            new BufferedInputStream(
                                new FileInputStream(
                                    argv[0]))));
        } catch (FileNotFoundException e) {
            System.out.println("AtoB():  can''t find file " +
                argv[0] + ":\n" + e);
            return;
        }

        // (3) Read the entire contents of the specified BASE 64 encoded
        //     blob into a String() object throwing away any
        //     headers beginning with HEADER and any trailers beginning
        //     with TRAILER
        try {
            while ((asciiBASE64BlobChunk = inputBlob.readLine()) != null) {
                if (!(asciiBASE64BlobChunk.startsWith(HEADER)) &&
                    !(asciiBASE64BlobChunk.startsWith(TRAILER))) {
                    asciiBASE64Blob += asciiBASE64BlobChunk.trim();
                }
            }
        } catch (IOException e) {
            System.out.println("AtoB():  Unexpected BASE64 " +
                "encoded error encountered in readLine():\n" +
                e);
        }

        // (4) Close the DataInputStream() object
        try {
            inputBlob.close();
        } catch (IOException e) {
            System.out.println("AtoB():  Unexpected BASE64 " +
                "encoded error encountered in close():\n" + e);
        }
		
        // (5) Decode the ASCII BASE 64 blob enclosed in the
        //     String() object into a BINARY BASE 64 byte[] object

        binaryBASE64Blob = com.netscape.osutil.OSUtil.AtoB(asciiBASE64Blob);

        // (6) Finally, print the actual AtoB blob to the
        //     specified output file
        try {
            outputBlob = new FileOutputStream(argv[1]);
        } catch (IOException e) {
            System.out.println("AtoB():  unable to open file " +
                argv[1] + " for writing:\n" + e);
            return;
        }

        try {
            outputBlob.write(binaryBASE64Blob);
        } catch (IOException e) {
            System.out.println("AtoB():  I/O error " +
                "encountered during write():\n" +
                e);
        }

        try {
            outputBlob.close();
        } catch (IOException e) {
            System.out.println("AtoB():  Unexpected error " +
                "encountered while attempting to close() " +
                argv[1] + ":\n" + e);
        }
    }
}

