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
package com.netscape.cmscore.security;

public class Provider extends java.security.Provider {

    /**
     *
     */
    private static final long serialVersionUID = -8050884788034389693L;

    public Provider() {
        super("CMS", 1.4,
                "Provides Signature and Message Digesting");

        /////////////////////////////////////////////////////////////
        // Signature
        /////////////////////////////////////////////////////////////

        put("Signature.SHA1withDSA", "org.mozilla.jss.provider.DSASignature");

        put("Alg.Alias.Signature.DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.DSS", "SHA1withDSA");
        put("Alg.Alias.Signature.SHA/DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.SHA-1/DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.SHA1/DSA", "SHA1withDSA");
        put("Alg.Alias.Signature.DSAWithSHA1", "SHA1withDSA");
        put("Alg.Alias.Signature.SHAwithDSA", "SHA1withDSA");

        put("Signature.MD5/RSA", "org.mozilla.jss.provider.MD5RSASignature");
        put("Signature.MD2/RSA", "org.mozilla.jss.provider.MD2RSASignature");
        put("Signature.SHA-1/RSA",
                "org.mozilla.jss.provider.SHA1RSASignature");

        put("Alg.Alias.Signature.SHA1/RSA", "SHA-1/RSA");

        /////////////////////////////////////////////////////////////
        // Message Digesting
        /////////////////////////////////////////////////////////////

    }
}
