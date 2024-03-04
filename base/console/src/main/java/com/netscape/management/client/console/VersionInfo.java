/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.console;

import com.netscape.management.client.util.*;

/**
 * Provides version information for Console.
 * The version data is stored in the "console.properties" file.
 */
public class VersionInfo {

    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.console.versioninfo");

    /**
     * Returns version number for the Console.
     *
     * @return  Console Version Number
     */
    public static String getVersionNumber() {
        return _resource.getString("console","versionNumber");
    }

    /**
     * Returns major version number for the Console.
     *
     * @return  Console Major Version Number
     */
    public static String getMajorVersionNumber() {
        return _resource.getString("console","majorVersionNumber");
    }

    /**
      * Returns build number for the Console.
      *
      * @return  Console Build Number
      */
    public static String getBuildNumber() {
        return _resource.getString("console","buildNumber");
    }
}
