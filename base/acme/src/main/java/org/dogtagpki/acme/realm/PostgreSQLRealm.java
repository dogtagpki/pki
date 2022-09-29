//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.realm;

import com.netscape.cms.realm.PKIPostgreSQLRealm;
import com.netscape.cms.realm.RealmConfig;

/**
 * @author Endi S. Dewata
 */
public class PostgreSQLRealm extends PKIPostgreSQLRealm {

    @Override
    public void setConfig(RealmConfig config) {
        super.setConfig(config);
        if(config.getParameter("statements") == null) {
            this.config.setParameter("statements", "/usr/share/pki/acme/realm/postgresql/statements.conf");
        }
    }
}
