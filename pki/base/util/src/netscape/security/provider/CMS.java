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
package netscape.security.provider;

import java.security.AccessController;
import java.security.Provider;

/**
 * The CMS Security Provider.
 */

public final class CMS extends Provider {

    /**
     *
     */
    private static final long serialVersionUID = 1065207998900104219L;
    private static final String INFO = "CMS " +
            "(DSA key/parameter generation; DSA signing; " +
            "SHA-1, MD5 digests; SecureRandom; X.509 certificates)";

    public CMS() {
        /* We are the SUN provider */
        super("CMS", 1.0, INFO);

        AccessController.doPrivileged(new java.security.PrivilegedAction() {
            public Object run() {
                /*
                * Certificates
                */
                put("CertificateFactory.X.509", "netscape.security.provider.X509CertificateFactory");
                put("Alg.Alias.CertificateFactory.X.509", "X.509");
                return null;
            }
        });
    }
}
