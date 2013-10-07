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
package com.netscape.cmscore.security;

import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;

public class PWUtil {

    public static Password readPasswordFromStream() throws PasswordCallback.GiveUpException {

        StringBuffer buf = new StringBuffer();
        String passwordString = "";
        int c;
        // System.out.println( "about to do read" );
        try {
            while ((c = System.in.read()) != -1) {
                char ch = (char) c;

                // System.out.println( "read [" + ch + "]" );
                // System.out.println( "char is [" + ch + "]" );
                if (ch != '\r') {
                    if (ch != '\n') {
                        buf.append(ch);
                    } else {
                        passwordString = buf.toString();
                        buf.setLength(0);
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("READ EXCEPTION");
        }

        // memory problem?
        //      String passwordString = in.readLine();
        //            System.out.println( "done read" );
        //            System.out.println( " password recieved is ["
        //                              + passwordString + "]" );
        if (passwordString == null) {
            throw new PasswordCallback.GiveUpException();
        }

        if (passwordString.equals("")) {
            throw new PasswordCallback.GiveUpException();
        }

        // System.out.println( "returning pw" );
        return (new Password(passwordString.toCharArray()));

    }
}
