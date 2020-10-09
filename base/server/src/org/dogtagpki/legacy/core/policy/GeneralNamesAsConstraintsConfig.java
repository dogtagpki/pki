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

import org.dogtagpki.legacy.core.policy.GeneralNameUtil.GeneralNameAsConstraintsConfig;
import org.dogtagpki.legacy.core.policy.GeneralNameUtil.GeneralNameConfig;
import org.dogtagpki.legacy.core.policy.GeneralNameUtil.GeneralNamesConfig;
import org.dogtagpki.legacy.policy.IGeneralNamesAsConstraintsConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

public class GeneralNamesAsConstraintsConfig extends GeneralNamesConfig implements
        IGeneralNamesAsConstraintsConfig {
    public GeneralNamesAsConstraintsConfig(
            String name,
            IConfigStore config,
            boolean isValueConfigured,
            boolean isPolicyEnabled)
            throws EBaseException {
        super(name, config, isValueConfigured, isPolicyEnabled);
    }

    protected GeneralNameConfig newGeneralNameConfig(
            String name, IConfigStore config,
            boolean isValueConfigured, boolean isPolicyEnabled)
            throws EBaseException {
        return new GeneralNameAsConstraintsConfig(name, config,
                isValueConfigured, isPolicyEnabled);
    }
}
