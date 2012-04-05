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
package com.netscape.cmscore.dbs;

import java.io.Serializable;
import java.util.Date;

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;

import com.netscape.certsrv.dbs.certdb.IRevocationInfo;

/**
 * A class represents a certificate revocation info. This
 * object is written as an attribute of certificate record
 * which essentially signifies a revocation act.
 * <P>
 *
 * @author galperin
 * @version $Revision$, $Date$
 */
public class RevocationInfo implements IRevocationInfo, Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -157323417902547417L;
    private Date mRevocationDate = null;
    private CRLExtensions mCRLEntryExtensions = null;

    /**
     * Constructs revocation info.
     */
    public RevocationInfo() {
    }

    /**
     * Constructs revocation info used by revocation
     * request implementation.
     *
     * @param reason if not null contains CRL entry extension
     *            that specifies revocation reason
     * @see CRLReasonExtension
     */
    public RevocationInfo(Date revocationDate, CRLExtensions exts) {
        mRevocationDate = revocationDate;
        mCRLEntryExtensions = exts;
    }

    /**
     * Retrieves revocation date.
     */
    public Date getRevocationDate() {
        return mRevocationDate;
    }

    /**
     * Retrieves CRL extensions.
     */
    public CRLExtensions getCRLEntryExtensions() {
        return mCRLEntryExtensions;
    }
}
