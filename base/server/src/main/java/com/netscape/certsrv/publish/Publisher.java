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
package com.netscape.certsrv.publish;

import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.cmscore.base.ConfigStore;

import netscape.ldap.LDAPConnection;

/**
 * Class for publishing certificate or crl to database store.
 */
public abstract class Publisher {

    public static final String PROP_PREDICATE = "predicate";
    public static final String PROP_ENABLE = "enable";
    public static final String PROP_IMPLNAME = "implName";

    /**
     * Initialize from config store.
     *
     * @param config the configuration store to initialize from.
     * @exception DBException initialization failed due to Ldap error.
     * @exception EBaseException initialization failed.
     */
    public abstract void init(ConfigStore config) throws EBaseException, DBException;

    /**
     * Return config store.
     */
    public abstract ConfigStore getConfigStore();

    /**
     * Returns the implementation name.
     */
    public abstract String getImplName();

    /**
     * Returns the description of the publisher.
     */
    public abstract String getDescription();

    /**
     * Returns the current instance parameters.
     */
    public abstract Vector<String> getInstanceParams();

    /**
     * Returns the initial default parameters.
     */
    public abstract Vector<String> getDefaultParams();

    /**
     * Publish an object.
     *
     * @param conn a Ldap connection
     *            (null for non-LDAP publishing)
     * @param dn dn of the ldap entry to publish cert
     *            (null for non-LDAP publishing)
     * @param object object to publish
     *            (java.security.cert.X509Certificate or,
     *            java.security.cert.X509CRL)
     * @exception DBException publish failed.
     */
    public abstract void publish(LDAPConnection conn, String dn, Object object)
            throws DBException;

    /**
     * Unpublish an object.
     *
     * @param conn the Ldap connection
     *            (null for non-LDAP publishing)
     * @param dn dn of the ldap entry to unpublish cert
     *            (null for non-LDAP publishing)
     * @param object object to unpublish
     *            (java.security.cert.X509Certificate)
     * @exception DBException unpublish failed.
     */
    public abstract void unpublish(LDAPConnection conn, String dn, Object object)
            throws DBException;
}
