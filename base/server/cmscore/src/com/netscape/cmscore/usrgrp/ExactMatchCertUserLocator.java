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
package com.netscape.cmscore.usrgrp;

import java.security.cert.X509Certificate;

import netscape.ldap.LDAPException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.ICertUserLocator;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;

/**
 * This interface defines a strategy on how to match
 * the incoming certificate(s) with the certificate(s)
 * in the scope. It matches the "description" field which contains a
 * stringied certificate.
 *
 * @author thomask
 * @author cfu
 * @version $Revision$, $Date$
 */
public class ExactMatchCertUserLocator implements ICertUserLocator {
    private IUGSubsystem mUG = null;

    /**
     * Constructs certificate matching agent.
     */
    public ExactMatchCertUserLocator() {
    }

    /**
     * Retrieves description.
     */
    public String getDescription() {
        return "A subject is authenticated if its first" +
                " certificate can be matched with one of the" +
                " certificate in the scope";
    }

    /**
     * Do the cert-user mapping
     */
    public IUser locateUser(Certificates certs) throws
            EUsrGrpException, LDAPException, ELdapException {
        mUG = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

        X509Certificate certificates[] = certs.getCertificates();

        if (certificates == null)
            return null;
        int pos = 0;

        if (certificates[0].getSubjectDN().toString().equals(
                certificates[0].getIssuerDN().toString())) {
            pos = certificates.length - 1;
        }

        String filter = "description=" +
                mUG.getCertificateString(certificates[pos]);

        return mUG.findUsersByCert(filter);
    }
}
