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

import java.io.IOException;
import org.mozilla.jss.netscape.security.util.Utils;

public class Keyring {

    private static String keyring = "@u";
    private static String keyType = "user";

    /**
     * Get Key ID from keyname
     *
     * @param keyName Name of the key
     * @return Key ID
     */
    public static long getKeyID(String keyName) {
        String[] cmd = { "keyctl", "search", keyring, keyType, keyName };
        try {
            String output = Utils.exec(cmd, null);
            return Long.parseLong(output);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return -1;
    }

    /**
     * Get password from keyring
     *
     * @param keyName Name of the key
     * @param output_format Output format
     * @return Value of the key available in keyring
     * @throws IllegalArgumentException
     */
    public static String getPassword(String keyName, String output_format)
            throws IllegalArgumentException {

        // Assign a default value to retrieve
        if (output_format.isEmpty())
            output_format = "raw";

        String mode;
        if (output_format.toLowerCase() == "raw")
            mode = "pipe";
        else if (output_format.toLowerCase() == "hex")
            mode = "read";
        else
            throw new IllegalArgumentException("output_format must be one of [\'raw\', \'hex\'].");

        long keyID = getKeyID(keyName);

        String[] cmd = {"keyctl", mode, String.valueOf(keyID)};
        try {
            String output = Utils.exec(cmd, null);
            return output;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return null;

    }

}
