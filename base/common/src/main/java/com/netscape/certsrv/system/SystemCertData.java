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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="SystemCertData")
@XmlAccessorType(XmlAccessType.FIELD)
public class SystemCertData {

    @XmlElement
    protected String tag;

    @XmlElement
    protected String nickname;

    @XmlElement
    protected String token;

    @XmlElement
    protected String profile;

    @XmlElement
    protected String type;

    @XmlElement
    protected String keySize;

    @XmlElement
    protected String keyCurveName;

    @XmlElement
    protected String request;

    @XmlElement
    protected String subjectDN;

    @XmlElement
    protected String opFlags;

    @XmlElement
    protected String opFlagsMask;

    @XmlElement
    protected String cert;

    @XmlElement
    protected String req_ext_oid;

    @XmlElement
    protected String req_ext_critical;

    @XmlElement
    protected String req_ext_data;

    @XmlElement
    protected String[] dnsNames;

    public SystemCertData() {
        // required for JAXB
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
        if (req_ext_critical.equals("true"))
            return true;
        else
            return false;
    }

    public String[] getDNSNames() {
        return dnsNames;
    }

    public void setDNSNames(String[] dnsNames) {
        this.dnsNames = dnsNames;
    }

    /**
     * @return the certificate operation flags
     */
    public String getOpFlags() {
        return opFlags;
    }

    /**
     * @param The certificate operation flags. It is a comma separated list of usages including: encrypt, decrypt, sign, sign_recover, verify, verify_recover, wrap, unwrap and derive.
     */
    public void setOpFlags(String opFlags) {
        this.opFlags = opFlags;
    }

    /**
     * @return the certificate operation mask
     */
    public String getOpFlagsMask() {
        return opFlagsMask;
    }

    /**
     * @param The certificate operation mask. It is a comma separated list of usages including: encrypt, decrypt, sign, sign_recover, verify, verify_recover, wrap, unwrap and derive.
     */
    public void setOpFlagsMask(String opFlagsMask) {
        this.opFlagsMask = opFlagsMask;
    }

    @Override
    public String toString() {
        return "SystemCertData["
            + "tag=" + tag
            + ", nickname=" + nickname
            + ", token=" + token
            + ", profile=" + profile
            + ", type=" + type
            + ", keySize=" + keySize
            + ", keyCurveName=" + keyCurveName
            + ", request=" + request
            + ", subjectDN=" + subjectDN
            + ", cert=" + cert
            + ", req_ext_oid=" + req_ext_oid
            + ", req_ext_critical=" + req_ext_critical
            + ", req_ext_data=" + req_ext_data
            + ", dnsNames=" + (dnsNames == null ? null : Arrays.asList(dnsNames))
            + "]";
    }

}
