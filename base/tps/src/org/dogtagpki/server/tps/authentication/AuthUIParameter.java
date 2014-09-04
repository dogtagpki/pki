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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps.authentication;

import java.util.HashMap;

import com.netscape.certsrv.base.EBaseException;

/*
 * AuthUIParameters is a class for per locale parameter sets
 *
 * @author cfu
 */
public class AuthUIParameter {

    private String paramId;
    /*
     *   auths.instance.<authInst>.ui.id.<param>.name.<locale>=<name>
     *   auths.instance.<authInst>.ui.id.<param>.description.<locale>=<description>
     *  e.g.
     *   auths.instance.ldap1.ui.id.PASSWORD.description.en=LDAP Password
     *   auths.instance.ldap1.ui.id.PASSWORD.name.en=LDAP Password
     *   auths.instance.ldap1.ui.id.UID.description.en=LDAP User ID
     *   auths.instance.ldap1.ui.id.UID.name.en=LDAP User ID
     *
     *  for each id param <locale, name>
     */
    private HashMap<String, String> uiParamIdName;
    private HashMap<String, String> uiParamIdDescription;

    public AuthUIParameter(String id)
            throws EBaseException {
        paramId = id;
        uiParamIdName = new HashMap<String, String>();
        uiParamIdDescription = new HashMap<String, String>();
    }

    public void setParamName(String locale, String name) {
        uiParamIdName.put(locale, name);
    }

    public String getParamName(String locale) {
        return uiParamIdName.get(locale);
    }

    public void setParamDescription(String locale, String desc) {
        uiParamIdDescription.put(locale, desc);
    }

    public String getParamDescription(String locale) {
        return uiParamIdDescription.get(locale);
    }

    public String toString(String locale) {
        String name = getParamName(locale);
        if (name == null)
            name = getParamName("en");

        String desc = getParamDescription(locale);
        if (desc == null)
            desc = getParamDescription("en");

        String typeValue = "string";

        if(paramId.equals("PASSWORD")){
            typeValue = "password";
        }

        String string =
                "id=" + paramId +
                        "&name=" + name +
                        "&desc=" + desc +
                        "&type=" + typeValue +
                        "&option=";
        return string;
    }
}
