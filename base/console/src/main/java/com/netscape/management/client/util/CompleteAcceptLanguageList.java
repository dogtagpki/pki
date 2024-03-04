/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.util;

import netscape.ldap.*;
import java.util.*;


/**
 * CompleteAcceptLanguageList class definition.
 *
 * @see http://lemming/as40/javadoc/ for documentation
 * @see http://lemming/as40/javadoc/Main.java for sample
 */
public class CompleteAcceptLanguageList {

    public static String getDefaultAcceptLanguage(LDAPConnection wire,
            String dn) throws LDAPException {
        return getAttrValForDN(wire, dn, "defaultAcceptLanguage");
    }

    public static void setDefaultAcceptLanguage(LDAPConnection wire,
            String dn, String result) throws LDAPException {
        setAttrValForDn(wire, dn, "defaultAcceptLanguage", result);
    }

    public static String getAttrValForDN(LDAPConnection wire,
            String dn, String attr) throws LDAPException {
        if (!wire.isConnected())
            throw new LDAPException();
        LDAPEntry search_result;
        search_result = wire.read(dn);
        Enumeration set =
                (search_result.getAttribute(attr)).getStringValues();
        if (!set.hasMoreElements())
            throw new LDAPException();
        return (String) set.nextElement();
    }

    public static void setAttrValForDn(LDAPConnection wire, String dn,
            String attr, String value) throws LDAPException {
        LDAPModification modifying_info;
        LDAPEntry search_result;
        LDAPAttribute new_value = new LDAPAttribute(attr, value);

        if (!wire.isConnected())
            throw new LDAPException();

        wire.read(dn);
        try {
            getAttrValForDN(wire, dn, attr);
            modifying_info = new LDAPModification(LDAPModification.REPLACE,
                    new_value);
        } catch (Throwable attrNotpresent) {
            modifying_info =
                    new LDAPModification(LDAPModification.ADD, new_value);
        }
        wire.modify(dn, modifying_info);

        return;
    }

    /**
     * static method to create a Vector of acceptlanguage
     */
    public static Vector createCompleteAcceptLanguage(
            String acceptlang, String defaultacceptlang) {
        String system_list;
        system_list = acceptlang + "," + defaultacceptlang + ",en";

        AcceptLanguageList complete_list =
                new AcceptLanguageList(system_list);
        return complete_list.getList();
    }
}
