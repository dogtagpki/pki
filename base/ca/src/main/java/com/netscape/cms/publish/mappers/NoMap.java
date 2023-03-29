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
package com.netscape.cms.publish.mappers;

import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.publish.Mapper;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

import netscape.ldap.LDAPConnection;

/**
 * No Map
 */
public class NoMap extends Mapper implements IExtendedPluginInfo {

    public ConfigStore mConfig;

    /**
     * constructor if initializing from config store.
     */
    public NoMap() {
    }

    @Override
    public String[] getExtendedPluginInfo() {
        String params[] = {
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-ldappublish-mapper-simplemapper",
                IExtendedPluginInfo.HELP_TEXT + ";Describes how to form the name of the entry to publish to"
            };

        return params;
    }

    @Override
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * for initializing from config store.
     */
    @Override
    public void init(ConfigStore config) throws EBaseException {
        mConfig = config;
    }

    /**
     * Maps a X500 subject name to LDAP entry.
     * Uses DN pattern to form a DN for a LDAP base search.
     *
     * @param conn the LDAP connection.
     * @param obj the object to map.
     * @exception ELdapException if any LDAP exceptions occured.
     */
    @Override
    public String map(LDAPConnection conn, Object obj)
            throws ELdapException {
        return null;
    }

    @Override
    public String map(LDAPConnection conn, Request req, Object obj)
            throws ELdapException {
        return null;
    }

    @Override
    public String getImplName() {
        return "NoMap";
    }

    @Override
    public String getDescription() {
        return "NoMap";
    }

    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<>();
        return v;
    }

    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<>();
        return v;
    }

}
