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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/**
 *
 */
package com.netscape.certsrv.key;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestIdAdapter;

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyData")
@XmlAccessorType(XmlAccessType.NONE)
public class KeyData {
    @XmlElement
    String wrappedPrivateData;

    @XmlElement
    String nonceData;

    @XmlElement
    String p12Data;

    @XmlElement
    String algorithm;

    @XmlElement
    Integer size;

    @XmlElement
    String additionalWrappedPrivateData;
    // Optionally used for importing a shared secret from TKS to TPS
    // Will contain wrapped shared secret data.
    // Can be used for anything in other scenarios

    @XmlElement
    @XmlJavaTypeAdapter(RequestIdAdapter.class)
    RequestId requestID;

    @XmlElement
    String encryptAlgorithmOID;

    @XmlElement
    String wrapAlgorithm;

    @XmlElement
    String type;

    @XmlElement
    String publicKey;

    public KeyData() {
        // required for JAXB (defaults)
    }

    /**
     * @return the wrappedPrivateData
     */
    public String getWrappedPrivateData() {
        return wrappedPrivateData;
    }

    /**
     * @param wrappedPrivateData the wrappedPrivateData to set
     */
    public void setWrappedPrivateData(String wrappedPrivateData) {
        this.wrappedPrivateData = wrappedPrivateData;
    }

    public String getAdditionalWrappedPrivateData() {
        return additionalWrappedPrivateData;
    }


    public void setAdditionalWrappedPrivateData(String additionalWrappedPrivateData) {
        this.additionalWrappedPrivateData = additionalWrappedPrivateData;
    }

    /**
     * @return the nonceData
     */

    public String getNonceData() {
        return nonceData;
    }

    /**
     * @param nonceData the nonceData to set
     */

    public void setNonceData(String nonceData) {
        this.nonceData = nonceData;
    }

    /**
     * @return the p12Data
     */
    public String getP12Data() {
        return p12Data;
    }

    /**
     * @param p12Data the p12Data to set
     */
    public void setP12Data(String p12Data) {
        this.p12Data = p12Data;
    }

    /**
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * @param algorithm the algorithm to set
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * @return the size
     */
    public Integer getSize() {
        return size;
    }

    /**
     * @param size the size to set
     */
    public void setSize(Integer size) {
        this.size = size;
    }

    /**
     * ID for the recovery request
     * @return recovery request id
     */
    public RequestId getRequestID() {
        return requestID;
    }

    /**
     * Set request ID
     * @param requestID
     */
    public void setRequestID(RequestId requestID) {
        this.requestID = requestID;
    }

    /**
     * Symmetric and Asymmetric keys will be returned either encrypted or wrapped
     * by the client provided symmetric key.  Which mechanism is used depends on the
     * capabilities of the server (and the HSM behind it).  One (and only one) of
     * encryptionAlgorithm or wrapAlgorithm will be set.
     *
     * @return OID of encryption algorithm used to wrap the secret.
     */
    public String getEncryptAlgorithmOID() {
        return encryptAlgorithmOID;
    }

    public void setEncryptAlgorithmOID(String encryptAlgorithmOID) {
        this.encryptAlgorithmOID = encryptAlgorithmOID;
    }

    /**
     * @return name (as known by JSS) of algorithm used to wrap secret if key
     *         wrapping is used
     */
    public String getWrapAlgorithm() {
        return wrapAlgorithm;
    }

    public void setWrapAlgorithm(String wrapAlgorithm) {
        this.wrapAlgorithm = wrapAlgorithm;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
