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

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;
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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((additionalWrappedPrivateData == null) ? 0 : additionalWrappedPrivateData.hashCode());
        result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
        result = prime * result + ((encryptAlgorithmOID == null) ? 0 : encryptAlgorithmOID.hashCode());
        result = prime * result + ((nonceData == null) ? 0 : nonceData.hashCode());
        result = prime * result + ((p12Data == null) ? 0 : p12Data.hashCode());
        result = prime * result + ((publicKey == null) ? 0 : publicKey.hashCode());
        result = prime * result + ((requestID == null) ? 0 : requestID.hashCode());
        result = prime * result + ((size == null) ? 0 : size.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((wrapAlgorithm == null) ? 0 : wrapAlgorithm.hashCode());
        result = prime * result + ((wrappedPrivateData == null) ? 0 : wrappedPrivateData.hashCode());
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
        KeyData other = (KeyData) obj;
        if (additionalWrappedPrivateData == null) {
            if (other.additionalWrappedPrivateData != null)
                return false;
        } else if (!additionalWrappedPrivateData.equals(other.additionalWrappedPrivateData))
            return false;
        if (algorithm == null) {
            if (other.algorithm != null)
                return false;
        } else if (!algorithm.equals(other.algorithm))
            return false;
        if (encryptAlgorithmOID == null) {
            if (other.encryptAlgorithmOID != null)
                return false;
        } else if (!encryptAlgorithmOID.equals(other.encryptAlgorithmOID))
            return false;
        if (nonceData == null) {
            if (other.nonceData != null)
                return false;
        } else if (!nonceData.equals(other.nonceData))
            return false;
        if (p12Data == null) {
            if (other.p12Data != null)
                return false;
        } else if (!p12Data.equals(other.p12Data))
            return false;
        if (publicKey == null) {
            if (other.publicKey != null)
                return false;
        } else if (!publicKey.equals(other.publicKey))
            return false;
        if (requestID == null) {
            if (other.requestID != null)
                return false;
        } else if (!requestID.equals(other.requestID))
            return false;
        if (size == null) {
            if (other.size != null)
                return false;
        } else if (!size.equals(other.size))
            return false;
        if (type == null) {
            if (other.type != null)
                return false;
        } else if (!type.equals(other.type))
            return false;
        if (wrapAlgorithm == null) {
            if (other.wrapAlgorithm != null)
                return false;
        } else if (!wrapAlgorithm.equals(other.wrapAlgorithm))
            return false;
        if (wrappedPrivateData == null) {
            if (other.wrappedPrivateData != null)
                return false;
        } else if (!wrappedPrivateData.equals(other.wrappedPrivateData))
            return false;
        return true;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(KeyData.class).createMarshaller();
        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static KeyData fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(KeyData.class).createUnmarshaller();
        return (KeyData) unmarshaller.unmarshal(new StringReader(xml));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.writeValueAsString(this);
    }

    public static KeyData fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.readValue(json, KeyData.class);
    }

    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
