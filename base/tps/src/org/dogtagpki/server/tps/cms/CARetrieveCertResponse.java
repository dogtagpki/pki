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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.cms;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Hashtable;

import netscape.security.x509.X509CertImpl;

import org.dogtagpki.server.connector.IRemoteRequest;

/**
 * CARetrieveCertResponse is the class for the response to
 * CA Remote Request: retrieveCertificate()
 *
 */
public class CARetrieveCertResponse extends RemoteResponse
{
    public CARetrieveCertResponse(Hashtable<String, Object> ht) {
        nameValTable = ht;
    }

    public String getCertB64() {
        return (String) nameValTable.get(IRemoteRequest.CA_RESPONSE_Certificate_chain_b64);
    }

    public X509CertImpl getCert() {
        return (X509CertImpl) nameValTable.get(IRemoteRequest.CA_RESPONSE_Certificate_x509);
    }

    public String getRevocationReason() {
        return (String) nameValTable.get(IRemoteRequest.CA_RESPONSE_Certificate_RevocationReason);
    }

    public boolean isCertRevoked() {
        String retRevocationReason = getRevocationReason();
        if (retRevocationReason != null) {
            return true;
        }
        // revocationReason not found means cert not revoked
        return false;
    }

    /*
     * This is checking the validity;  Revocation check should be done by calling isCertRevoked()
     */
    public boolean isCertValid() {
        X509CertImpl cert = getCert();
        try {
            cert.checkValidity();
            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return false;
        }
    }
}
