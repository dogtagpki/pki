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
package com.netscape.cms.shares;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import com.netscape.certsrv.kra.IShare;

/**
 * Use Java's reflection API to leverage CMS's
 * old Share and JoinShares implementations.
 *
 * @deprecated
 * @version $Revision$ $Date$
 */
public class OldShare implements IShare {
    public Object mOldImpl = null;

    public OldShare() {
    }

    public void initialize(byte[] secret, int threshold) throws Exception {
        try {
            Class<?> c = Class.forName("com.netscape.cmscore.shares.Share");
            Class<?> types[] = { secret.getClass(), int.class };
            Constructor<?> con = c.getConstructor(types);
            Object params[] = { secret, Integer.valueOf(threshold) };
            mOldImpl = con.newInstance(params);
        } catch (Exception e) {
        }
    }

    public byte[] createShare(int sharenumber) {
        if (mOldImpl == null)
            return null;
        try {
            Class<?> types[] = { int.class };
            Class<?> c = mOldImpl.getClass();
            Method method = c.getMethod("createShare", types);
            Object params[] = { Integer.valueOf(sharenumber) };
            return (byte[]) method.invoke(mOldImpl, params);
        } catch (Exception e) {
            return null;
        }
    }
}
