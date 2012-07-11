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
package com.netscape.cmscore.cert;

import java.util.Comparator;
import java.util.Date;

import netscape.security.x509.X509CertImpl;

/**
 * Compares validity dates for use in sorting.
 *
 * @author kanda
 * @version $Revision$, $Date$
 */
public class CertDateCompare implements Comparator<X509CertImpl>, java.io.Serializable {

    private static final long serialVersionUID = -1784015027375808580L;

    public CertDateCompare() {
    }

    public int compare(X509CertImpl cert1, X509CertImpl cert2) {
        Date d1 = null;
        Date d2 = null;

        try {
            d1 = cert1.getNotAfter();
            d2 = cert2.getNotAfter();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (d1 == d2)
            return 0;
        if (d1.after(d2))
            return 1;
        else
            return -1;
    }
}
