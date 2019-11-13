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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;

public class LDAPConfigurator {

    public final static Logger logger = LoggerFactory.getLogger(LDAPConfigurator.class);

    LDAPConnection connection;

    public LDAPConfigurator(LDAPConnection connection) {
        this.connection = connection;
    }

    public LDAPEntry getEntry(String dn) throws Exception {

        logger.info("LDAPConfigurator: Getting LDAP entry " + dn);

        try {
            return connection.read(dn);

        } catch (LDAPException e) {

            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.warn("LDAP entry not found: " + dn);
                return null;

            } else {
                String message = "Unable to get LDAP entry " + dn + ": " + e;
                logger.error(message);
                throw new Exception(message, e);
            }
        }
    }
}
