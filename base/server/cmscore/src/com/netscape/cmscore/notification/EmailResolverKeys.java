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
package com.netscape.cmscore.notification;

import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.notification.IEmailResolverKeys;

/**
 * Email resolver keys as input to email resolvers
 * <P>
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class EmailResolverKeys implements IEmailResolverKeys {
    /**
     *
     */
    private static final long serialVersionUID = -8823197350102151516L;
    private Hashtable<String, Object> mKeys = null;

    public EmailResolverKeys() {
        mKeys = new Hashtable<String, Object>();
    }

    /**
     * sets a key with key name and the key
     *
     * @param name key name
     * @param key key
     * @exception com.netscape.certsrv.base.EBaseException NullPointerException
     */
    public void set(String name, Object key) throws EBaseException {
        try {
            mKeys.put(name, key);
        } catch (NullPointerException e) {
            System.out.println(e.toString());
            throw new EBaseException("EmailResolverKeys.set()");
        }
    }

    /**
     * returns the key to which the specified name is mapped in this
     * key set
     *
     * @param name key name
     * @return the named email resolver key
     */
    public Object get(String name) {
        return mKeys.get(name);
    }

    /**
     * removes the name and its corresponding key from this
     * key set. This method does nothing if the named
     * key is not in the key set.
     *
     * @param name key name
     */
    public void delete(String name) {
        mKeys.remove(name);
    }

    /**
     * returns an enumeration of the key names in this key
     * set. Use the Enumeration methods on the returned object to
     * fetch the elements sequentially.
     *
     * @return an enumeration of the values in this key set
     * @see java.util.Enumeration
     */
    public Enumeration<String> getElements() {
        return mKeys.keys();
    }
}
