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

import java.security.cert.X509Certificate;
import java.util.Hashtable;

import org.dogtagpki.server.connector.IRemoteRequest;

/**
 * CAEnrollCertResponse is the class for the response to
 * CA Remote Request: enrollCertificate()
 *
 */
public class CAEnrollCertResponse extends RemoteResponse
{
    public CAEnrollCertResponse(Hashtable<String, Object> ht) {
        nameValTable = ht;
    }

    public String getRenewedCertB64() {
        return (String) nameValTable.get(IRemoteRequest.CA_RESPONSE_RenewedCertificate_b64);
    }

    public String getRenewedCertSerialHex() {
        return (String) nameValTable.get(IRemoteRequest.CA_RESPONSE_RenewedCertificate_serial);
    }

    public String getRenewedCertSubjectDN() {
        return (String) nameValTable.get(IRemoteRequest.CA_RESPONSE_RenewedCertificate_SubjectDN);
    }

    public X509Certificate getRenewedCert() {
        return (X509Certificate) nameValTable.get(IRemoteRequest.CA_RESPONSE_RenewedCertificate_x509);
    }
}
