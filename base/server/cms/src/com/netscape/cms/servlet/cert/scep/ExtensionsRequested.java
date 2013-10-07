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
package com.netscape.cms.servlet.cert.scep;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.Extension;

public class ExtensionsRequested implements CertAttrSet {

    public static final String NAME = "EXTENSIONS_REQUESTED";

    public static final String KUE_DIGITAL_SIGNATURE = "kue_digital_signature";
    public static final String KUE_KEY_ENCIPHERMENT = "kue_key_encipherment";

    private String kue_digital_signature = "false";
    private String kue_key_encipherment = "false";

    private Vector<Extension> exts = new Vector<Extension>();

    public ExtensionsRequested(Object stuff) throws IOException {
        ByteArrayInputStream is = new ByteArrayInputStream((byte[]) stuff);

        try {
            decode(is);
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException(e.getMessage());
        }
    }

    public void encode(OutputStream out)
            throws CertificateException, IOException {
    }

    public void decode(InputStream in)
            throws CertificateException, IOException {
        DerValue derVal = new DerValue(in);

        construct(derVal);
    }

    public void set(String name, Object obj)
            throws CertificateException, IOException {
    }

    public Object get(String name)
            throws CertificateException, IOException {
        if (name.equalsIgnoreCase(KUE_DIGITAL_SIGNATURE)) {
            return kue_digital_signature;
        }
        if (name.equalsIgnoreCase(KUE_KEY_ENCIPHERMENT)) {
            return kue_key_encipherment;
        }

        throw new IOException("Unsupported attribute queried");
    }

    public void delete(String name)
            throws CertificateException, IOException {
    }

    public Enumeration<String> getAttributeNames() {
        return (new Vector<String>()).elements();
    }

    public String getName() {
        return NAME;
    }

    /**
     * construct - expects this in the inputstream (from the router):
     *
     * 211 30 31: SEQUENCE {
     * 213 06 10: OBJECT IDENTIFIER '2 16 840 1 113733 1 9 8'
     * 225 31 17: SET {
     * 227 04 15: OCTET STRING, encapsulates {
     * 229 30 13: SEQUENCE {
     * 231 30 11: SEQUENCE {
     * 233 06 3: OBJECT IDENTIFIER keyUsage (2 5 29 15)
     * 238 04 4: OCTET STRING
     * : 03 02 05 A0
     * : }
     * : }
     * : }
     *
     * or this (from IRE client):
     *
     * 262 30 51: SEQUENCE {
     * 264 06 9: OBJECT IDENTIFIER extensionReq (1 2 840 113549 1 9 14)
     * 275 31 38: SET {
     * 277 30 36: SEQUENCE {
     * 279 30 34: SEQUENCE {
     * 281 06 3: OBJECT IDENTIFIER subjectAltName (2 5 29 17)
     * 286 04 27: OCTET STRING
     * : 30 19 87 04 D0 0C 3E 6F 81 03 61 61 61 82 0C 61
     * : 61 61 2E 6D 63 6F 6D 2E 63 6F 6D
     * : }
     * : }
     * : }
     * : }
     */
    private void construct(DerValue dv) throws IOException {

        DerInputStream stream = null;

        try { // try decoding as sequence first

            stream = dv.toDerInputStream();

            stream.getDerValue(); // consume stream
            stream.reset();

            stream.getSequence(2); // consume stream
        } catch (IOException ioe) {
            // if it failed, the outer sequence may be
            // encapsulated in an octet string, as in the first
            // example above

            byte[] octet_string = dv.getOctetString();

            // Make a new input stream from the byte array,
            // and re-parse it as a sequence.

            dv = new DerValue(octet_string);

            stream = dv.toDerInputStream();
            stream.getSequence(2); // consume stream
        }

        // now, the stream will be in the correct format
        stream.reset();

        while (true) {
            DerValue ext_dv = null;
            try {
                ext_dv = stream.getDerValue();
            } catch (IOException ex) {
                break;
            }

            Extension ext = new Extension(ext_dv);
            exts.addElement(ext);
        }

    }

    public Vector<Extension> getExtensions() {
        return exts;
    }

}
