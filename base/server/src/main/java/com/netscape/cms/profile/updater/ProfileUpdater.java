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
package com.netscape.cms.profile.updater;

import java.util.Locale;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IConfigTemplate;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * This interface represents an updater that will be
 * called when the request's state changes.
 *
 * @version $Revision$, $Date$
 */
public abstract class ProfileUpdater implements IConfigTemplate {

    /**
     * Initializes this default policy.
     *
     * @param profile owner of this policy
     * @param config configuration store
     * @exception EProfileException failed to initialize
     */
    public abstract void init(Profile profile, ConfigStore config) throws EProfileException;

    /**
     * Retrieves configuration store.
     *
     * @return configuration store
     */
    public abstract ConfigStore getConfigStore();

    /**
     * Notifies of state change.
     *
     * @param req request
     * @param status The status to check for.
     * @exception EProfileException failed to populate
     */
    public abstract void update(Request req, RequestStatus status)
            throws EProfileException;

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale user locale
     * @return output policy name
     */
    public abstract String getName(Locale locale);

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale user locale
     * @return output policy description
     */
    public abstract String getText(Locale locale);
}
