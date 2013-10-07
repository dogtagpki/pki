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
package com.netscape.cmscore.util;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintWriter;

public class ExceptionFormatter {

    /**
     * Routines for pretty-printing java exceptions
     * prints okay in a single-line.
     */
    /*
     * Take an exception stacktrace, and reformat it so that is
     * prints okay in a single-line.
     */

    public static String getStackTraceAsString(Throwable e) {
        String returnvalue = e.toString();

        PipedOutputStream po = new PipedOutputStream();
        try (PipedInputStream pi = new PipedInputStream(po)) {

            PrintWriter ps = new PrintWriter(po);
            e.printStackTrace(ps);
            ps.flush();

            int avail = pi.available();
            byte[] b = new byte[avail];

            pi.read(b, 0, avail);
            returnvalue = new String(b);
        } catch (Exception ex) {
        }
        return returnvalue;
    }

    /* test code below */

    public static void test()
            throws TestException {
        throw new TestException("** testexception **");
    }

    public static void main(String[] argv) {
        try {
            test();
        } catch (Exception e) {
            System.out.println("\n------- Exception.toString() ------");
            System.out.println(e.toString());
            System.out.println("\n------- Exception.printStackTrace() ------");
            e.printStackTrace();
            System.out.println("\n------- ExceptionFormatter.format() ------");
            System.out.println(ExceptionFormatter.getStackTraceAsString(e));
        }
    }

}

class TestException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = -5737463439434110385L;

    public TestException() {
    }

    public TestException(String s) {
        super(s);
    }

}
