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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.PolicyDefault;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileParameter;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.IRequest;

public class PolicyDefaultFactory {

    public static PolicyDefault create(IRequest request, Locale locale, IPolicyDefault def) throws EPropertyException {
        PolicyDefault ret = new PolicyDefault();
        ret.setName(def.getName(locale));
        ret.setText(def.getText(locale));

        Enumeration<String> defNames  = def.getValueNames();
        while (defNames.hasMoreElements()) {
            String defName = defNames.nextElement();
            ProfileAttribute attr = new ProfileAttribute(
                    defName,
                    def.getValue(defName, locale, request),
                    (Descriptor) def.getValueDescriptor(locale, defName));
            ret.addAttribute(attr);
        }
        return ret;
    }

    public static PolicyDefault create(IArgBlock params, Locale locale, IPolicyDefault def) throws EPropertyException {
        PolicyDefault ret = new PolicyDefault();
        ret.setName(def.getName(locale));
        ret.setText(def.getText(locale));

        Enumeration<String> defNames  = def.getValueNames();
        while (defNames.hasMoreElements()) {
            String defName = defNames.nextElement();
            ProfileAttribute attr = new ProfileAttribute(
                    defName,
                    params.getValueAsString(defName, ""),
                    (Descriptor) def.getValueDescriptor(locale, defName));
            ret.addAttribute(attr);
        }
        return ret;
    }

    public static PolicyDefault create(Locale locale, IPolicyDefault def, String classId) throws EPropertyException {
        PolicyDefault ret = new PolicyDefault();
        ret.setName(def.getName(locale));
        ret.setText(def.getText(locale));
        ret.setClassId(classId);

        Enumeration<String> defNames  = def.getValueNames();
        while (defNames.hasMoreElements()) {
            String defName = defNames.nextElement();
            ProfileAttribute attr = new ProfileAttribute();
            attr.setName(defName);
            attr.setDescriptor((Descriptor) def.getValueDescriptor(locale, defName));
            ret.addAttribute(attr);
        }

        List<ProfileParameter> pList = new ArrayList<ProfileParameter>();
        Enumeration<String> paramNames  = def.getConfigNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            ProfileParameter p = new ProfileParameter(paramName, def.getConfig(paramName));
            pList.add(p);
        }
        ret.setParams(pList);

        return ret;
    }

}
