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
package com.netscape.admin.certsrv;

import com.netscape.management.client.util.*;
import java.security.cert.CertificateException;
import netscape.security.x509.*;
import java.util.*;

/**
 * UIMapper Registry
 *
 * This Registry keeps track of the mappings between the certificate
 * attribute class and the UI Mapper.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.IUIMapper
 */
public class UIMapperRegistry {

    /*==========================================================
     * variables
     *==========================================================*/
    private static UIMapperRegistry mSelf = null;
    private static Hashtable mAttrContent = new Hashtable();

	/*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * register new certificate attribute.
     *
     * @param className fully qualified class name implementing CertAttrSet
     * @param oid the string representation of the object identifier
     * @param extentionName the name of the attribute.
     * @param mapperClassName fully qualified class name implementing UI
     */
    /* XXX WE DON'T NEED THIS
    public static void registerCertAttrUI(String className, String oid,
                                    String attrName, String mapperClassName)
        throws ClassNotFoundException, CertificateException
    {
        Class extClass, mapClass;
        extClass = Class.forName(className);
        mapClass = Class.forName(mapperClassName);
        OIDMap.addAttribute(className,oid,attrName);
        registerCertAttrUI(attrName,mapperClassName);
    }
    */

    /**
     * internal register new cert attr
     *
     * @param className fully qualified class name implementing CertAttrSet
     * @param extentionName the name of the attribute.
     * @param mapperClassName fully qualified class name implementing UI
     */
    public static void registerCertAttrUI(String attrName, String mapperClassName) {
        mAttrContent.put(attrName, mapperClassName);
    }

    /**
     * Retrieve all certificate attribute name
     */
    public static Enumeration getCertAttrNames() {
        return mAttrContent.keys();
    }

    /**
     * Retrieve all extension UI Mappers
     */
    public static Enumeration getCertAttrUIs() {
        return mAttrContent.elements();
    }

    /**
     * Get instance of UI Mapper by certificate attribute name
     *
     * @param certAttrClassName certificate attribute name
     */
    public static IUIMapper getCertAttrUI(String certAttrClassName)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException
    {
        String mapperClassName = (String) mAttrContent.get(certAttrClassName);
        Class mapClass = Class.forName(mapperClassName);
        IUIMapper instance = (IUIMapper) mapClass.newInstance();
        return instance;
    }

    //load the static stuff here
    static {
        loadUIMappings();
    }

    //loads the standard UI components
    private static void loadUIMappings() {
        /*
        UIMapperRegistry registry = UIMapperRegistry.getUIMapperRegistry();
        registry.addExtensionMapping
        */
    }

}

