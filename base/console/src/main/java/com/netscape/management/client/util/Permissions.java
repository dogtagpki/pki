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

package com.netscape.management.client.util;

import java.lang.reflect.Method;

//import netscape.security.PrivilegeManager;
//import netscape.security.ForbiddenTargetException;

/**
 * A class to get properties of permissions in an Applet environment.
 */
public class Permissions {
    static final public boolean grantStandard() {
        if (!isApplet())
            return true;

        /*
        try
    {
           PrivilegeManager.enablePrivilege("UniversalConnect");
           PrivilegeManager.enablePrivilege("UniversalAwtEventQueueAccess");
           PrivilegeManager.enablePrivilege("UniversalThreadGroupAccess");
           Debug.println("Permissions:granted standard privileges");
        return true;
    }
        catch (ForbiddenTargetException e)
    {
           Debug.println("Permissions: unable to grant standard privileges:" + e);
        return false;
    }
        */

        return true;
    }

    static final public boolean grant(String capability) {
        if (!isApplet())
            return true;

        /*
        try
    {
           PrivilegeManager.enablePrivilege(capability);
           Debug.println("Permissions:granted " + capability);
        return true;
    }
        catch (ForbiddenTargetException e)
    {
           Debug.println(0, "Permissions: unable to grant " + capability + " privilege:" + e);
        return false;
    }
        */

        return true;
    }

    static public boolean isApplet() {
        SecurityManager sec = System.getSecurityManager();

        if (sec == null)
            return false;

        if (sec.toString().startsWith("netscape.security.AppletSecurity"))
            return true;

        return false;
    }

    protected static Method enablePrivilege = null;

    static public Method getEnablePrivilegeMethod() {
        if (!isApplet())
            return null;

        if (enablePrivilege != null)
            return enablePrivilege;

        Class c;

        try {
            c = Class.forName("netscape.security.PrivilegeManager");
        } catch (ClassNotFoundException cnfe) {
            return null;
        }

        Method[] m = c.getMethods();

        for (int i = 0 ; i < m.length ; i++) {
            if (m[i].getName().equals("enablePrivilege"))
                return (enablePrivilege = m[i]);
        }

        Debug.println("Permissions:getEnablePrivilegeMethod():method not found");
        return null;
    }
}
