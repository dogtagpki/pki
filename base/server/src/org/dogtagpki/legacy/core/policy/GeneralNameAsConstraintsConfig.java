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
package org.dogtagpki.legacy.core.policy;

import org.dogtagpki.legacy.policy.IGeneralNameAsConstraintsConfig;
import org.mozilla.jss.netscape.security.x509.GeneralName;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * convenience class for policies use.
 */
public class GeneralNameAsConstraintsConfig extends GeneralNameConfig implements
        IGeneralNameAsConstraintsConfig {

    public GeneralNameAsConstraintsConfig(
            String name,
            IConfigStore config,
            boolean isValueConfigured,
            boolean isPolicyEnabled)
            throws EBaseException {
        super(name, config, isValueConfigured, isPolicyEnabled);
    }

    public GeneralName getGeneralName() {
        return mGeneralName;
    }

    /**
     * Form a general name from the value string.
     */
    public GeneralName formGeneralName(String choice, String value)
            throws EBaseException {
        return GeneralNameUtil.form_GeneralNameAsConstraints(choice, value);
    }
}
