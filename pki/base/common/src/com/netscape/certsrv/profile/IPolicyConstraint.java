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
package com.netscape.certsrv.profile;


import java.util.Locale;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.IConfigTemplate;
import com.netscape.certsrv.request.IRequest;


/**
 * This represents a constraint policy. A constraint policy
 * validates if the given request conforms to the set
 * rules.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface IPolicyConstraint extends IConfigTemplate {

    /**
     * Initializes this constraint policy.
     *
     * @param profile owner of this policy
     * @param config configuration store for this constraint
     * @exception EProfileException failed to initialize
     */
    public void init(IProfile profile, IConfigStore config)
        throws EProfileException;

    /**
     * Returns the corresponding configuration store
     * of this constraint policy.
     *
     * @return config store of this constraint
     */
    public IConfigStore getConfigStore();

    /**
     * Validates the request. The request is not modified
     * during the validation.
     *
     * @param request request to be validated
     * @exception ERejectException reject the given request
     */
    public void validate(IRequest request)
        throws ERejectException;

    /**
     * Returns localized description of this constraint.
     *
     * @param locale locale of the end-user
     * @return localized description of this constraint
     */
    public String getText(Locale locale);

    /**
     * Returns localized name of this constraint.
     *
     * @param locale locale of the end-user
     * @return localized name of this constraint
     */
    public String getName(Locale locale);

    /**
     * Checks if this constraint is applicable to the
     * given default policy.
     *
     * @param def default policy to be checked
     * @return true if this constraint can be applied to
     *              the given default policy
     */
    public boolean isApplicable(IPolicyDefault def);
}
