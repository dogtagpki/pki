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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.ca;

import java.util.Collection;

public interface KeyRetriever {
    /**
     * Retrieve the specified signing key from specified clone and
     * return to the KeyRetrieverRunner.
     *
     * A KeyRetriever MUST NOT import the cert and key to the NSSDB
     * itself.  It SHALL, if successful in retrieving the key and
     * certificate, return a Result which contains a PEM-encoded
     * X.509 certificate and a DER-encoded PKIArchiveOptions object
     * containing an EncryptedValue of the target private key
     * wrapped by the host authority's public key.
     *
     * Upon failure the KeyRetriever SHALL return null.
     */
    Result retrieveKey(String nickname, Collection<String> hostPorts);

    class Result {
        private byte[] certificate;
        private byte[] pkiArchiveOptions;

        public Result(byte[] certificate, byte[] pkiArchiveOptions) {
            this.certificate = certificate;
            this.pkiArchiveOptions = pkiArchiveOptions;
        }

        public byte[] getCertificate() {
            return certificate;
        }

        public byte[] getPKIArchiveOptions() {
            return pkiArchiveOptions;
        }
    }
}
