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
package com.netscape.cms.publish.publishers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Vector;

/**
 * Publisher utility class.
 *
 * @version $Revision$, $Date$
 */
public class PublisherUtils {
    public static void checkHost(String hostname) throws UnknownHostException {
        InetAddress.getByName(hostname);
    }

    public static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[4096];
        int len;

        while ((len = in.read(buf)) != -1) {
            out.write(buf, 0, len);
        }
    }

    public static void copyStream(BufferedReader in, OutputStreamWriter out) throws IOException {
        char[] buf = new char[4096];
        int len;

        while ((len = in.read(buf)) != -1) {
            out.write(buf, 0, len);
        }
    }

    /// Sorts an array of Strings.
    // Java currently has no general sort function.  Sorting Strings is
    // common enough that it's worth making a special case.
    public static void sortStrings(String[] strings) {
        // Just does a bubblesort.
        for (int i = 0; i < strings.length - 1; ++i) {
            for (int j = i + 1; j < strings.length; ++j) {
                if (strings[i].compareTo(strings[j]) > 0) {
                    String t = strings[i];

                    strings[i] = strings[j];
                    strings[j] = t;
                }
            }
        }
    }

    /// Returns a date string formatted in Unix ls style - if it's within
    // six months of now, Mmm dd hh:ss, else Mmm dd  yyyy.
    public static String lsDateStr(Date date) {
        long dateTime = date.getTime();

        if (dateTime == -1L)
            return "------------";
        long nowTime = System.currentTimeMillis();
        SimpleDateFormat formatter = new SimpleDateFormat();

        if (Math.abs(nowTime - dateTime) < 183L * 24L * 60L * 60L * 1000L)
            formatter.applyPattern("MMM dd hh:ss");
        else
            formatter.applyPattern("MMM dd yyyy");
        return formatter.format(date);
    }

    /**
     * compares contents two byte arrays returning true if exactly same.
     */
    static public boolean byteArraysAreEqual(byte[] a, byte[] b) {
        if (a.length != b.length)
            return false;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }

    /**
     * strips out double quotes around String parameter
     *
     * @param s the string potentially bracketed with double quotes
     * @return string stripped of surrounding double quotes
     */
    public static String stripQuotes(String s) {
        if (s == null) {
            return s;
        }

        if ((s.startsWith("\"")) && (s.endsWith("\""))) {
            return (s.substring(1, (s.length() - 1)));
        }

        return s;
    }

    /**
     * returns an array of strings from a vector of Strings
     * there'll be trouble if the Vector contains something other
     * than just Strings
     */
    public static String[] getStringArrayFromVector(Vector<String> v) {
        String s[] = new String[v.size()];

        v.copyInto(s);
        return s;
    }

}
