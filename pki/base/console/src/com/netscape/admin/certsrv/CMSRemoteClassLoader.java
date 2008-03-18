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
package com.netscape.admin.certsrv;

import java.util.Hashtable;
import java.io.IOException;
import com.netscape.admin.certsrv.connection.AdminConnection;

/**
 * The CMSRemoteClassLoader is designed to load classes from remote
 * Certificate Servers. Classes are acquired via the admin channel
 * used by the Certificate Server console.
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @date	 	02/13/97
 * @see ClassLoader
 */
class CMSRemoteClassLoader extends ClassLoader {

    /*==========================================================
     * variables
     *==========================================================*/
    private Hashtable mCache = new Hashtable();     // stores classes
    private AdminConnection mAdmin;                     // srever entry point

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSRemoteClassLoader(CMSServerInfo info) {
        //mAdmin = info.getAdmin();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

	/**
	 * Attempts to load the named class.
	 *
	 * @param name the fully-qualified class name, in '.' form.
	 * @return the Class object of the named class.
	 * @throws ClassNotFoundException if the class cannot be found.
	 */
    public synchronized Class loadClass(String name, boolean resolve)
        throws ClassNotFoundException
    {
        Class c = (Class) mCache.get(name);

        if (c == null) {
            String path = name.replace('.', '/') + ".class";
            try {
                byte data[] = loadClassData(path);
                c = defineClass(name,data, 0, data.length);
                mCache.put(name, c);
            } catch (Exception e) {
            }
        }
        if (resolve)
            resolveClass(c);
        return c;

    }

	/**
	 * Attempts to load the named class.
	 *
	 * @param name the fully-qualified class name, in '.' form.
	 * @return the Class object of the named class.
	 * @throws ClassNotFoundException if the class cannot be found.
	 */
	public Class loadClass(String name) throws ClassNotFoundException {
        return this.loadClass(name, true);
    }

    /*==========================================================
	 * private methods
     *==========================================================*/

    /**
     * Retrieves the class specified by path from the server side.
     *
     * @param class name
     * @return an InputStream for the resource.
     * @throws Exception on any error while loading the resource.
     */
    private byte[] loadClassData(String path)
        throws EAdminException
    {
        //load the class here from server side
        return null;
    }

}
