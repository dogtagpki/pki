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
package netscape.security.extensions;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.*;
import java.util.*;

import java.security.cert.CertificateException;
import netscape.security.x509.*;
import netscape.security.util.*;

/**
 * This represents the CertificateScopeOfUse extension
 * as defined in draft-thayes-cert-scope-00
 *
 * CertificateScopeEntry ::= SEQUENCE {
 *   name GeneralName, -- pattern, as for NameConstraints
 *   portNumber INTEGER OPTIONAL
 * }
 * CertificateScopeOfUse ::= SEQUENCE OF CertificateScopeEntry
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CertificateScopeEntry {
    private GeneralName mGn = null;
    private BigInt mPort = null;

    /**
     * Constructs scope with der value.
     */
    public CertificateScopeEntry(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for PolicyQualifierInfo.");
        }
        DerValue gn = val.data.getDerValue();

        mGn = new GeneralName(gn);
        if (val.data.available() != 0) {
            mPort = val.data.getInteger();
        }
    }

    /**
     * Constructs scope wit
     */
    public CertificateScopeEntry(GeneralName gn, BigInt port) {
        mGn = gn;
        mPort = port; // optional
    }

    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        mGn.encode(tmp);
        if (mPort != null) {
            tmp.putInteger(mPort);
        }
        out.write(DerValue.tag_Sequence, tmp);
    }

    /**
     * Returns a GeneralName
     */
    public GeneralName getGeneralName() {
        return mGn;
    }

    /**
     * Returns a port
     */
    public BigInt getPort() {
        return mPort;
    }

    /**
     * Returns a printable representation of the CertificateRenewalWindow.
     */
    public String toString() {
        String s = super.toString() + "CertificateScopeEntry [\n";

        s += "GeneralName: " + mGn;
        if (mPort != null) {
            s += "PortNumber: " + mPort;
        }
        return (s + "]\n");
    }
}
