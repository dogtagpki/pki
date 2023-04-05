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
package com.netscape.cmscore.extensions;

import java.util.Enumeration;
import java.util.Hashtable;

import org.mozilla.jss.netscape.security.util.ObjectIdentifier;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.extensions.CMSExtension;
import com.netscape.certsrv.extensions.EExtensionsException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;

/**
 * Loads extension classes from configuration file and return
 * for a given extension name or OID.
 */
public class CMSExtensionsMap {
    public static String ID = "extensions";

    private static final String PROP_CLASS = "class";

    private Hashtable<String, CMSExtension> mName2Ext = new Hashtable<>();
    private Hashtable<String, CMSExtension> mOID2Ext = new Hashtable<>();
    private ConfigStore mConfig;

    /**
     * Create extensions from configuration store.
     * @param config the configuration store.
     */
    public void init(ConfigStore config) throws EBaseException {
        mConfig = config;

        Enumeration<String> sstores = mConfig.getSubStoreNames().elements();

        while (sstores.hasMoreElements()) {
            String name = sstores.nextElement();
            ConfigStore c = mConfig.getSubStore(name, ConfigStore.class);

            String className = c.getString(PROP_CLASS);
            CMSExtension ext = null;

            try {
                ext = (CMSExtension) Class.forName(className).getDeclaredConstructor().newInstance();
                ext.init(c);
                addExt(ext);
            } catch (Exception e) {
                throw new EExtensionsException("CMSExtensionsMap: " + e.getMessage(), e);
            }
        }
    }

    public void addExt(CMSExtension ext) throws EBaseException {
        String name = ext.getName();
        ObjectIdentifier oid = ext.getOID();

        if (name == null || oid == null) {
            throw new EExtensionsException(
                    CMS.getUserMessage("CMS_EXTENSION_INCORRECT_IMPL",
                            ext.getClass().getName()));
        }
        mName2Ext.put(name, ext);
        mOID2Ext.put(oid.toString(), ext);
    }

    /**
     * startup - does nothing.
     */
    public void startup() throws EBaseException {
    }

    /**
     * shutdown - does nothing.
     */
    public void shutdown() {
    }

    /**
     * Get configuration store.
     */
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Returns subsystem ID
     */
    public String getId() {
        return ID;
    }

    /**
     * sets subsystem ID
     */
    public void setId(String Id) {
    }

    /**
     * Get the extension class by name.
     *
     * @param name name of the extension
     * @return the extension class.
     */
    public CMSExtension getByName(String name) {
        return mName2Ext.get(name);
    }

    /**
     * Get the extension class by its OID.
     *
     * @param oid - the OID of the extension.
     * @return the extension class.
     */
    public CMSExtension getByOID(ObjectIdentifier oid) {
        return mOID2Ext.get(oid.toString());
    }
}
