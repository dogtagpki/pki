/** Authors:
*     Dinesh Prasanth M K <dmoluguw@redhat.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the Lesser GNU General Public License as published by
* the Free Software Foundation; either version 3 of the License or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
*  along with this program; if not, write to the Free Software Foundation,
* Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
* Copyright (C) 2018 Red Hat, Inc.
* All rights reserved.
**/

package com.netscape.cmsutil.util;

public class Keyring {

    private static String keyring = "@u";
    private static String keyType = "user";


    public static long getKeyID(String keyName) {
        String cmd = "keyctl search " + keyring + " " + keyType + " " + keyName;
        return Long.parseLong(Utils.exec(cmd, ""));
    }

    public static String getPassword(String keyName, String output_format) throws Exception {

        // Assign a default value to retrieve
        if (output_format.isEmpty())
            output_format = "raw";

        String mode;
        if (output_format.toLowerCase() == "raw")
            mode = "pipe";
        else if (output_format.toLowerCase() == "hex")
            mode = "read";
        else
            throw new Exception("output_format must be one of [\'raw\', \'hex\'].");

        long keyID = getKeyID(keyName);

        String cmd = "keyctl " + mode + " " + keyID;

        return Utils.exec(cmd, "");

    }

}
