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

import netscape.security.util.ObjectIdentifier;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.extensions.EExtensionsException;
import com.netscape.certsrv.extensions.ICMSExtension;

/**
 * Loads extension classes from configuration file and return
 * for a given extension name or OID.
 */
public class CMSExtensionsMap implements ISubsystem {
    public static String ID = "extensions";

    private static CMSExtensionsMap mInstance = new CMSExtensionsMap();

    public static final CMSExtensionsMap getInstance() {
        return mInstance;
    }

    private CMSExtensionsMap() {
    }

    private static final String PROP_CLASS = "class";

    private Hashtable<String, ICMSExtension> mName2Ext = new Hashtable<String, ICMSExtension>();
    private Hashtable<String, ICMSExtension> mOID2Ext = new Hashtable<String, ICMSExtension>();
    @SuppressWarnings("unused")
    private ISubsystem mOwner;
    private IConfigStore mConfig = null;

    /**
     * Create extensions from configuration store.
     *
     * @param config the configuration store.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mOwner = owner;
        mConfig = config;

        Enumeration<String> sstores = mConfig.getSubStoreNames();

        while (sstores.hasMoreElements()) {
            String name = sstores.nextElement();
            IConfigStore c = mConfig.getSubStore(name);

            String className = c.getString(PROP_CLASS);
            ICMSExtension ext = null;

            try {
                ext = (ICMSExtension) Class.forName(className).newInstance();
                ext.init(this, c);
                addExt(ext);
            } catch (ClassNotFoundException e) {
                throw new EExtensionsException(
                        CMS.getUserMessage("CMS_EXTENSION_CLASS_NOT_FOUND", className));
            } catch (IllegalAccessException e) {
                throw new EExtensionsException(
                        CMS.getUserMessage("CMS_EXTENSION_INSTANTIATE_ERROR",
                                className, e.toString()));
            } catch (InstantiationException e) {
                throw new EExtensionsException(
                        CMS.getUserMessage("CMS_EXTENSION_INSTANTIATE_ERROR",
                                className, e.toString()));
            } catch (ClassCastException e) {
                throw new EExtensionsException(
                        CMS.getUserMessage("CMS_EXTENSION_INVALID_IMPL", className));
            }
        }
    }

    public void addExt(ICMSExtension ext) throws EBaseException {
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
    public IConfigStore getConfigStore() {
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
    public ICMSExtension getByName(String name) {
        return mName2Ext.get(name);
    }

    /**
     * Get the extension class by its OID.
     *
     * @param oid - the OID of the extension.
     * @return the extension class.
     */
    public ICMSExtension getByOID(ObjectIdentifier oid) {
        return mOID2Ext.get(oid.toString());
    }
}
