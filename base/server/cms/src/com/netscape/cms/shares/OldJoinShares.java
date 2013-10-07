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

import com.netscape.certsrv.kra.IJoinShares;

/**
 * Use Java's reflection API to leverage CMS's
 * old Share and JoinShares implementations.
 *
 * @deprecated
 * @version $Revision$ $Date$
 */
public class OldJoinShares implements IJoinShares {

    public Object mOldImpl = null;

    public OldJoinShares() {
    }

    public void initialize(int threshold) throws Exception {
        Class<?> c = Class.forName("com.netscape.cmscore.shares.JoinShares");
        Class<?> types[] = { int.class };
        Constructor<?> con = c.getConstructor(types);
        Object params[] = { Integer.valueOf(threshold) };
        mOldImpl = con.newInstance(params);
    }

    public void addShare(int shareNum, byte[] share) {
        try {
            Class<?> types[] = { int.class, share.getClass() };
            Class<?> c = mOldImpl.getClass();
            Method method = c.getMethod("addShare", types);
            Object params[] = { Integer.valueOf(shareNum), share };
            method.invoke(mOldImpl, params);
        } catch (Exception e) {
        }
    }

    public int getShareCount() {
        if (mOldImpl == null)
            return -1;
        try {
            Class<?> types[] = null;
            Class<?> c = mOldImpl.getClass();
            Method method = c.getMethod("getShareCount", types);
            Object params[] = null;
            Integer result = (Integer) method.invoke(mOldImpl, params);
            return result.intValue();
        } catch (Exception e) {
            return -1;
        }
    }

    public byte[] recoverSecret() {
        if (mOldImpl == null)
            return null;
        try {
            Class<?> types[] = null;
            Class<?> c = mOldImpl.getClass();
            Method method = c.getMethod("recoverSecret", types);
            Object params[] = null;
            return (byte[]) method.invoke(mOldImpl, params);
        } catch (Exception e) {
            return null;
        }
    }
}
