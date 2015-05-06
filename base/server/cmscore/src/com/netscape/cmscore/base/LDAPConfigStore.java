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
// (C) 2007, 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmscore.base;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Map;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ILdapConnFactory;

/**
 * LDAPConfigStore:
 * Extends PropConfigStore with methods to load/save from/to file for
 * persistent storage. This is a configuration store agent who
 * reads data from an LDAP entry.
 * <P>
 *
 * @version $Revision$, $Date$
 * @see PropConfigStore
 */
public class LDAPConfigStore extends PropConfigStore implements IConfigStore {

    private ILdapConnFactory dbFactory;
    private String dn;
    private String attr;
    private LDAPAttribute[] createAttrs;

    /**
     *
     */
    private static final long serialVersionUID = 3642124526598175633L;

    /**
     * Constructs an LDAP configuration store.
     * <P>
     *
     * @param dbFactory Database connection factory
     * @param dn Distinguished name of record containing config store
     * @param attr Name of attribute containing config store
     * @param createAttrs Set of initial attributes if creating the entry.  Should
     *              contain cn, objectclass and possibly other attributes.
     *
     * @exception EBaseException failed to create file configuration
     */
    public LDAPConfigStore(
        ILdapConnFactory dbFactory,
        String dn, LDAPAttribute[] createAttrs, String attr
    ) {
        super(null);  // top-level store without a name

        this.dbFactory = dbFactory;
        this.dn = dn;
        this.createAttrs = createAttrs;
        this.attr = attr;
    }

    @Override
    public void save(OutputStream out, String header) {
        try (PrintWriter writer = new PrintWriter(out)) {
            Map<String, String> map = getProperties();
            for (String k : map.keySet()) {
                writer.println(k + "=" + map.get(k));
            }
        }
    }

    /**
     * Commit the configuration to the database.
     *
     * All uses of LDAPProfileStore at time of writing call with
     * createBackup=false, so the argument is ignored.
     *
     * If backup becomes necessary, the constructor should be
     * modified to take a String backupAttr, and the existing
     * content be copied to that attribute.
     *
     * @param createBackup Ignored.
     */
    public void commit(boolean createBackup) throws EBaseException {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        save(data, null);

        LDAPAttribute configAttr = new LDAPAttribute(attr, data.toByteArray());

        LDAPConnection conn = dbFactory.getConn();

        // first attempt to modify; if modification fails (due
        // to no such object), try and add the entry instead.
        try {
            try {
                commitModify(conn, configAttr);
            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                    commitAdd(conn, configAttr);
                } else {
                    throw e;
                }
            }
        } catch (LDAPException e) {
            throw new EBaseException(
                "Error writing LDAPConfigStore '"
                + dn + "': " + e.toString()
            );
        } finally {
            dbFactory.returnConn(conn);
        }
    }

    /**
     * Update the record via an LDAPModification.
     *
     * @param conn LDAP connection.
     * @param configAttr Config store attribute.
     * @return true on success, false if the entry does not exist.
     */
    private void commitModify(LDAPConnection conn, LDAPAttribute configAttr)
        throws LDAPException
    {
        LDAPModification ldapMod =
            new LDAPModification(LDAPModification.REPLACE, configAttr);
        conn.modify(dn, ldapMod);
    }

    /**
     * Add the LDAPEntry via LDAPConnection.add.
     *
     * @param conn LDAP connection.
     * @param configAttr Config store attribute.
     * @return true on success, false if the entry already exists.
     */
    private void commitAdd(LDAPConnection conn, LDAPAttribute configAttr)
        throws LDAPException
    {
        LDAPAttributeSet attrSet = new LDAPAttributeSet(createAttrs);
        attrSet.add(configAttr);
        LDAPEntry ldapEntry = new LDAPEntry(dn, attrSet);
        conn.add(ldapEntry);
    }
}
