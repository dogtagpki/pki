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

import javax.ws.rs.core.MultivaluedMap;
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
    public static final String TAG = "tag";
    public static final String NICKNAME = "nickname";
    public static final String TOKEN = "token";
    public static final String KEY_TYPE = "keyType";
    public static final String KEY_ALGORITHM = "keyAlgorithm";
    public static final String SIGNING_ALGORITHM = "signingAlgorithm";
    public static final String KEY_SIZE = "keySize";
    public static final String KEY_CURVENAME = "keyCurveName";
    public static final String REQUEST = "request";
    public static final String SUBJECT_DN = "subjectDN";
    public static final String CERT = "cert";
    public static final String CERT_CHAIN = "certChain";

    @XmlElement
    protected String tag;

    @XmlElement
    protected String nickname;

    @XmlElement
    protected String token;

    @XmlElement
    protected String keyType;

    @XmlElement
    protected String keyAlgorithm;

    @XmlElement
    protected String signingAlgorithm;

    @XmlElement
    protected String keySize;

    @XmlElement
    protected String keyCurveName;

    @XmlElement
    protected String request;

    @XmlElement
    protected String subjectDN;

    @XmlElement
    protected String cert;

    @XmlElement
    protected String certChain;

    public SystemCertData() {
        // required for JAXB
    }

    public SystemCertData(MultivaluedMap<String, String> form) {
        tag = form.getFirst(TAG);
        nickname = form.getFirst(NICKNAME);
        token = form.getFirst(TOKEN);
        keyType = form.getFirst(KEY_TYPE);
        keyAlgorithm = form.getFirst(KEY_ALGORITHM);
        signingAlgorithm = form.getFirst(SIGNING_ALGORITHM);
        keySize = form.getFirst(KEY_SIZE);
        keyCurveName = form.getFirst(KEY_CURVENAME);
        request = form.getFirst(REQUEST);
        subjectDN = form.getFirst(SUBJECT_DN);
        cert = form.getFirst(CERT);
        certChain = form.getFirst(CERT_CHAIN);
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

    /**
     * @return the keyType
     */
    public String getKeyType() {
        return keyType;
    }

    /**
     * @param keyType the keyType to set
     */
    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    /**
     * @return the keyAlgorithm
     */
    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    /**
     * @param keyAlgorithm the keyAlgorithm to set
     */
    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    /**
     * @return the signingAlgorithm
     */
    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    /**
     * @param signingAlgorithm the signingAlgorithm to set
     */
    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
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
     * @return the certChain
     */
    public String getCertChain() {
        return certChain;
    }

    /**
     * @param certChain the certChain to set
     */
    public void setCertChain(String certChain) {
        this.certChain = certChain;
    }

}
