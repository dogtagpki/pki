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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.dbs.certdb;

import java.util.Vector;

/**
 * @author thomask
 * @author kanda
 * @version $Revision$, $Date$
 */
public class RenewableCertificateCollection {
    Vector<Object> mToRenew = null;
    Vector<Object> mToNotify = null;

    public RenewableCertificateCollection() {
    }

    public Vector<Object> getRenewable() {
        return mToRenew;
    }

    public Vector<Object> getNotifiable() {
        return mToNotify;
    }

    public void addCertificate(String renewalFlag, Object o) {
        if (renewalFlag.equals(ICertRecord.AUTO_RENEWAL_ENABLED)) {
            if (mToRenew == null)
                mToRenew = new Vector<Object>();
            mToRenew.addElement(o);
        }
        if (renewalFlag.equals(ICertRecord.AUTO_RENEWAL_DISABLED)) {
            if (mToNotify == null)
                mToNotify = new Vector<Object>();
            mToNotify.addElement(o);
        }
    }
}