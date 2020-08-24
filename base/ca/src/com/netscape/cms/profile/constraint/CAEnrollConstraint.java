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
package com.netscape.cms.profile.constraint;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;

/**
 * This class represents an abstract class for CA enrollment
 * constraint.
 */
public abstract class CAEnrollConstraint extends EnrollConstraint {

    /**
     * Constructs a CA enrollment constraint.
     */
    public CAEnrollConstraint() {
        super();
    }

    /**
     * Retrieves the CA certificate.
     */
    public X509CertImpl getCACert() throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        return ca.getCACert();
    }
}
