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
package com.netscape.certsrv.ocsp;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmsutil.ocsp.Request;
import com.netscape.cmsutil.ocsp.SingleResponse;

/**
 * This class represents the generic interface for an Online Certificate
 * Status Protocol (OCSP) store. Users can plugin different OCSP stores
 * by extending this class. For example, imagine that if a user wants to
 * use the corporate LDAP server for revocation checking, then the user
 * would merely create a new class that extends this class (e. g. -
 * "public interface ICorporateLDAPStore extends IOCSPStore").
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface IOCSPStore {

    public boolean isByName();

    public void init(ConfigStore config, DBSubsystem dbSubsystem) throws EBaseException;

    public void startup() throws EBaseException;

    public void shutdown();

    /**
     * Check against the database for status.
     */
    public SingleResponse processRequest(Request req) throws Exception;

    /**
     * This method retrieves the configuration parameters associated with this
     * OCSP store.
     * <P>
     *
     * @return NameValuePairs all configuration items
     */
    public NameValuePairs getConfigParameters();

    /**
     * This method stores the configuration parameters specified by the
     * passed-in Name Value pairs object.
     * <P>
     *
     * @param pairs a name-value pair object
     * @exception EBaseException an illegal name-value pair
     */
    public void setConfigParameters(NameValuePairs pairs)
            throws EBaseException;
}
