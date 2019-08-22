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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.profile;

import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.profile.IPolicyConstraint;
import com.netscape.certsrv.profile.PolicyConstraint;
import com.netscape.certsrv.profile.PolicyConstraintValue;
import com.netscape.certsrv.property.Descriptor;

public class PolicyConstraintFactory {

    public static PolicyConstraint create(Locale locale, IPolicyConstraint cons, String classId) {
        PolicyConstraint ret = new PolicyConstraint();
        ret.setName(cons.getName(locale));
        ret.setText(cons.getText(locale));
        ret.setClassId(classId);

        Enumeration<String> conNames = cons.getConfigNames();
        while (conNames.hasMoreElements()) {
            String conName = conNames.nextElement();
            PolicyConstraintValue dataVal =
                    new PolicyConstraintValue(conName, (Descriptor) cons.getConfigDescriptor(locale, conName),
                            cons.getConfig(conName));
            ret.addConstraint(dataVal);
        }

        return ret;
    }
}
