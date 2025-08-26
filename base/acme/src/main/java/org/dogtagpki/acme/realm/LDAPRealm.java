//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.realm;

import com.netscape.cms.realm.PKILDAPRealm;

import netscape.ldap.LDAPConnection;
import netscape.ldap.util.LDIF;
import netscape.ldap.util.LDIFRecord;

/**
 * @author Endi S. Dewata
 */
public class LDAPRealm extends PKILDAPRealm {

    public void createRealmSubtrees(LDAPConnection connection) throws Exception {

        logger.info("Creating ACME realm subtrees");

        String filename = "/usr/share/pki/acme/realm/ds/create.ldif";
        LDIF ldif = new LDIF(filename);

        while (true) {
            LDIFRecord record = ldif.nextRecord();
            if (record == null) break;

            importLDIFRecord(connection, record);
        }
    }

    @Override
    public void initRealm() throws Exception {

        LDAPConnection connection = null;
        try {
            connection = connFactory.getConn();

            createRealmSubtrees(connection);

        } finally {
            if (connection != null) connection.disconnect();
        }
    }
}
