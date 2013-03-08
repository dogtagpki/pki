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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import com.netscape.cmsutil.util.Utils;

/**
 * The BtoA class is a utility program designed to "translate" a BINARY
 * BASE 64 encoded blob into an ASCII BASE 64 encoded blob. It assumes
 * that the name of a data file is passed to the program via the command line,
 * and that the contents contain a blob encoded in a BINARY BASE 64
 * format.
 *
 * <P>
 * The program may be invoked as follows:
 *
 * <PRE>
 *
 *      BtoA &lt;input filename&gt; &lt;output filename&gt;
 *
 *      NOTE:  &lt;input filename&gt;   must contain a BINARY
 *                                BASE 64 encoded blob
 *
 *             &lt;output filename&gt;  contains an ASCII
 *                                BASE 64 encoded blob
 * </PRE>
 *
 * @version $Revision$, $Date$
 */
public class BtoA {
    // Define constants
    public static final int ARGC = 2;

    public static void main(String argv[]) {

        FileInputStream inputBlob = null;
        FileOutputStream outputBlob = null;

        // (1) Check that two arguments were submitted to the program
        if (argv.length != ARGC) {
            System.out.println("Usage:  BtoA " +
                    "<input filename> " +
                    "<output filename>");
            return;
        }

        // (2) Create a DataInputStream() object to the BASE 64
        //     encoded blob contained within the file
        //     specified on the command line
        try {
            inputBlob = new FileInputStream(argv[0]);
        } catch (FileNotFoundException e) {
            System.out.println("BtoA():  can''t find file " +
                    argv[0] + ":\n" + e);
            return;
        }

        // (3) Create a FileOutputStream() object to the BASE 64
        //     specified output file
        try {
            outputBlob = new FileOutputStream(argv[1]);
        } catch (IOException e) {
            System.out.println("BtoA():  unable to open file " +
                    argv[1] + " for writing:\n" + e);
            try {
                inputBlob.close();
            } catch (IOException e1) {
            }
            return;
        }

        // (4) Convert the BINARY BASE 64 blob into an ASCII BASE 64 blob

        try {
            byte data[] = new byte[inputBlob.available()];
            inputBlob.read(data);
            String out = Utils.base64encode(data);
            outputBlob.write(out.getBytes());
        } catch (IOException e) {
            System.out.println("BtoA():  Unexpected BASE64 " +
                    "encoded error encountered:\n" +
                    e);
        }

        // (5) Close the DataInputStream() object
        try {
            inputBlob.close();
        } catch (IOException e) {
            System.out.println("BtoA():  Unexpected input error " +
                    "encountered while attempting to close() " +
                    argv[0] + ":\n" + e);
        }

        // (6) Close the FileOutputStream() object
        try {
            outputBlob.close();
        } catch (IOException e) {
            System.out.println("BtoA():  Unexpected output error " +
                    "encountered while attempting to close() " +
                    argv[1] + ":\n" + e);
        }
    }
}
