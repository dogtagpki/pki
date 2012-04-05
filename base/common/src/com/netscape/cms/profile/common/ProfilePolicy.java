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
package com.netscape.cms.profile.common;

import com.netscape.certsrv.profile.IPolicyConstraint;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfilePolicy;

/**
 * This class implements a profile policy that
 * contains a default policy and a constraint
 * policy.
 *
 * @version $Revision$, $Date$
 */
public class ProfilePolicy implements IProfilePolicy {
    private String mId = null;
    private IPolicyDefault mDefault = null;
    private IPolicyConstraint mConstraint = null;

    public ProfilePolicy(String id, IPolicyDefault def, IPolicyConstraint constraint) {
        mId = id;
        mDefault = def;
        mConstraint = constraint;
    }

    public String getId() {
        return mId;
    }

    public IPolicyDefault getDefault() {
        return mDefault;
    }

    public IPolicyConstraint getConstraint() {
        return mConstraint;
    }
}
