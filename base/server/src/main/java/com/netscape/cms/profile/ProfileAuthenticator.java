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
package com.netscape.cms.profile;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.cmscore.request.Request;

/**
 * This interface represents an authenticator for profile.
 * An authenticator is responsibile for authenting
 * the end-user. If authentication is successful, request
 * can be processed immediately. Otherwise, the request will
 * be defered and manual approval is then required.
 *
 * @version $Revision$, $Date$
 */
public interface ProfileAuthenticator extends AuthManager {

    /**
     * Populates authentication specific information into the
     * request for auditing purposes.
     *
     * @param token authentication token
     * @param request request
     * @exception EProfileException failed to populate
     */
    public void populate(AuthToken token, Request request)
            throws EProfileException;

    /**
     * Checks if the value of the given property should be
     * serializable into the request. Passsword or other
     * security-related value may not be desirable for
     * storage.
     *
     * @param name property name
     * @return true if the property is not security related
     */
    public boolean isValueWriteable(String name);

    /**
     * Checks if this authenticator requires SSL client authentication.
     *
     * @return client authentication required or not
     */
    public boolean isSSLClientRequired();
}
