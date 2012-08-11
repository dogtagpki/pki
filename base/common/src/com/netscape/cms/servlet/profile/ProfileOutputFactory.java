//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.profile;

import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.request.IRequest;

public class ProfileOutputFactory {

    public static ProfileOutput create(IProfileOutput output, IRequest request, Locale locale) throws EProfileException {
        ProfileOutput ret = new ProfileOutput();
        ret.setName(output.getName(locale));
        ret.setText(output.getText(locale));

        Enumeration<String> attrNames  = output.getValueNames();
        while (attrNames.hasMoreElements()) {
            String attrName = attrNames.nextElement();
            ProfileAttribute attr = new ProfileAttribute(
                    attrName,
                    output.getValue(attrName, locale, request),
                    (Descriptor) output.getValueDescriptor(locale, attrName));
            ret.addAttribute(attr);
        }
        return ret;
    }

}
