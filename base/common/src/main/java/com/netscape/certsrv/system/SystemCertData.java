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

package com.netscape.certsrv.system;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class SystemCertData implements JSONSerializer {

    protected String token;
    protected String keyID;
    protected String keyAlgorithm;
    protected RequestId requestID;
    protected String signingAlgorithm;
    protected String type;
    protected String profile;
    protected CertId certID;
    protected String cert;

    public SystemCertData() {
    }

    /**
     * @return the token
     */
    public String getToken() {
        return token;
    }

    /**
     * @param token the token to set
     */
    public void setToken(String token) {
        this.token = token;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getKeyID() {
        return keyID;
    }

    public void setKeyID(String keyID) {
        this.keyID = keyID;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public RequestId getRequestID() {
        return requestID;
    }

    public void setRequestID(RequestId requestID) {
        this.requestID = requestID;
    }

    public CertId getCertID() {
        return certID;
    }

    public void setCertID(CertId certID) {
        this.certID = certID;
    }

    /**
     * @return the cert
     */
    public String getCert() {
        return cert;
    }

    /**
     * @param cert the cert to set
     */
    public void setCert(String cert) {
        this.cert = cert;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    @Override
    public String toString() {
        return "SystemCertData["
            + "token=" + token
            + ", profile=" + profile
            + ", type=" + type
            + ", keyID=" + keyID
            + ", keyAlgorithm=" + keyAlgorithm
            + ", requestID=" + requestID
            + ", certID=" + certID
            + ", cert=" + cert
            + ", signingAlgorithm=" + signingAlgorithm
            + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Objects.hash(
                certID,
                cert,
                keyID,
                keyAlgorithm,
                profile,
                requestID,
                token,
                type,
                signingAlgorithm);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SystemCertData other = (SystemCertData) obj;
        return Objects.equals(certID, other.certID)
                && Objects.equals(cert, other.cert)
                && Objects.equals(keyID, other.keyID)
                && Objects.equals(keyAlgorithm, other.keyAlgorithm)
                && Objects.equals(profile, other.profile)
                && Objects.equals(requestID, other.requestID)
                && Objects.equals(token, other.token)
                && Objects.equals(type, other.type)
                && Objects.equals(signingAlgorithm, other.signingAlgorithm);
    }

}
