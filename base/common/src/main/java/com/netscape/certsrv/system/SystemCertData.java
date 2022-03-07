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

import java.util.Arrays;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class SystemCertData implements JSONSerializer {

    protected String tag;

    protected String nickname;

    protected String token;

    protected String profile;

    protected String type;

    protected String keyID;
    protected String keyType;
    protected String keySize;

    protected String keyCurveName;
    protected String ecType;

    protected String keyAlgorithm;

    protected String requestType;
    protected String request;
    protected RequestId requestID;

    protected String subjectDN;

    protected String cert;

    protected String req_ext_oid;

    protected String req_ext_critical;

    protected String req_ext_data;

    protected String[] dnsNames;
    protected boolean adjustValidity;

    protected String signingAlgorithm;

    public SystemCertData() {
    }

    /**
     * @return the tag
     */
    public String getTag() {
        return tag;
    }

    /**
     * @param tag the tag to set
     */
    public void setTag(String tag) {
        this.tag = tag;
    }

    /**
     * @return the nickname
     */
    public String getNickname() {
        return nickname;
    }

    /**
     * @param nickname the nickname to set
     */
    public void setNickname(String nickname) {
        this.nickname = nickname;
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

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    /**
     * @return the keySize
     */
    public String getKeySize() {
        return keySize;
    }

    /**
     * @param keySize the keySize to set
     */
    public void setKeySize(String keySize) {
        this.keySize = keySize;
    }

    /**
     * @return the keyCurveName
     */
    public String getKeyCurveName() {
        return keyCurveName;
    }

    /**
     * @param keyCurveName the keyCurveName to set
     */
    public void setKeyCurveName(String keyCurveName) {
        this.keyCurveName = keyCurveName;
    }

    public String getEcType() {
        return ecType;
    }

    public void setEcType(String ecType) {
        this.ecType = ecType;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getRequestType() {
        return requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    /**
     * @return the request
     */
    public String getRequest() {
        return request;
    }

    /**
     * @param request the request to set
     */
    public void setRequest(String request) {
        this.request = request;
    }

    public RequestId getRequestID() {
        return requestID;
    }

    public void setRequestID(RequestId requestID) {
        this.requestID = requestID;
    }

    /**
     * @return the subjectDN
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * @param subjectDN the subjectDN to set
     */
    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
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

    /**
     * @return the req_ext_oid
     */
    public String getReqExtOID() {
        return req_ext_oid;
    }

    /**
     * @return the req_ext_data
     */
    public String getReqExtData() {
        return req_ext_data;
    }

    /**
     * @return the req_ext_critical
     */
    public boolean getReqExtCritical() {
        return "true".equals(req_ext_critical);
    }

    public String[] getDNSNames() {
        return dnsNames;
    }

    public void setDNSNames(String[] dnsNames) {
        this.dnsNames = dnsNames;
    }

    public boolean getAdjustValidity() {
        return adjustValidity;
    }

    public void setAdjustValidity(boolean adjustValidity) {
        this.adjustValidity = adjustValidity;
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
            + "tag=" + tag
            + ", nickname=" + nickname
            + ", token=" + token
            + ", profile=" + profile
            + ", type=" + type
            + ", keyID=" + keyID
            + ", keyType=" + keyType
            + ", keySize=" + keySize
            + ", keyCurveName=" + keyCurveName
            + ", ecType=" + ecType
            + ", keyAlgorithm=" + keyAlgorithm
            + ", requestType=" + requestType
            + ", request=" + request
            + ", requestID=" + requestID
            + ", subjectDN=" + subjectDN
            + ", cert=" + cert
            + ", req_ext_oid=" + req_ext_oid
            + ", req_ext_critical=" + req_ext_critical
            + ", req_ext_data=" + req_ext_data
            + ", dnsNames=" + (dnsNames == null ? null : Arrays.asList(dnsNames))
            + ", adjustValidity=" + adjustValidity
            + ", signingAlgorithm=" + signingAlgorithm
            + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(dnsNames);
        result = prime * result + Objects.hash(
                cert,
                keyID,
                keyType,
                keySize,
                keyCurveName,
                ecType,
                keyAlgorithm,
                nickname,
                profile,
                req_ext_critical,
                req_ext_data,
                req_ext_oid,
                requestType,
                request,
                requestID,
                subjectDN,
                tag,
                token,
                type,
                adjustValidity,
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
        return Objects.equals(cert, other.cert)
                && Arrays.equals(dnsNames, other.dnsNames)
                && Objects.equals(keyID, other.keyID)
                && Objects.equals(keyType, other.keyType)
                && Objects.equals(keySize, other.keySize)
                && Objects.equals(keyCurveName, other.keyCurveName)
                && Objects.equals(ecType, other.ecType)
                && Objects.equals(keyAlgorithm, other.keyAlgorithm)
                && Objects.equals(nickname, other.nickname)
                && Objects.equals(profile, other.profile)
                && Objects.equals(req_ext_critical, other.req_ext_critical)
                && Objects.equals(req_ext_data, other.req_ext_data)
                && Objects.equals(req_ext_oid, other.req_ext_oid)
                && Objects.equals(requestType, other.requestType)
                && Objects.equals(request, other.request)
                && Objects.equals(requestID, other.requestID)
                && Objects.equals(subjectDN, other.subjectDN)
                && Objects.equals(tag, other.tag) && Objects.equals(token, other.token)
                && Objects.equals(type, other.type)
                && Objects.equals(adjustValidity, other.adjustValidity)
                && Objects.equals(signingAlgorithm, other.signingAlgorithm);
    }

}
