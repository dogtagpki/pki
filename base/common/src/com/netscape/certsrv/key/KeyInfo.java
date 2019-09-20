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

import org.mozilla.jss.netscape.security.util.Utils;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;
import com.netscape.certsrv.dbs.keydb.KeyId;

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyInfo")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyInfo {

    @XmlElement
    protected String keyURL;

    @XmlElement
    protected String clientKeyID;

    @XmlElement
    protected String status;

    @XmlElement
    protected String algorithm;

    @XmlElement
    protected Integer size;

    @XmlElement
    protected String ownerName;

    @XmlElement
    private String publicKey;

    @XmlElement
    private String realm;

    public KeyInfo() {
        // required for JAXB (defaults)
    }

    /**
     * @return the keyURL
     */
    public String getKeyURL() {
        return keyURL;
    }

    /**
     * @param keyURL the keyURL to set
     */
    public void setKeyURL(String keyURL) {
        this.keyURL = keyURL;
    }

    /**
     * @return the key ID in the keyURL
     */
    @JsonIgnore
    public KeyId getKeyId() {
        String id = keyURL.substring(keyURL.lastIndexOf("/") + 1);
        return new KeyId(id);
    }

    /**
     * @return the clientKeyID
     */
    public String getClientKeyID() {
        return clientKeyID;
    }

    /**
     * @param clientKeyID the clientKeyID to set
     */
    public void setClientKeyID(String clientKeyID) {
        this.clientKeyID = clientKeyID;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    public String getOwnerName() {
        return ownerName;
    }

    public void setOwnerName(String ownerName) {
        this.ownerName = ownerName;
    }

    /**
     * Converts the stored base64 encoded public key to a byte
     * array and returns that value. Returns null, if public key is null.
     *
     * @return public key - as a byte array
     */
    public byte[] getPublicKey() {
        if (publicKey != null) {
            return Utils.base64decode(publicKey);
        }
        return null;
    }

    /**
     * Sets the binary data of the public key in a
     * base64 encoded string format.
     *
     * @param publicKey - if null, getPublicKey returns null.
     */
    public void setPublicKey(byte[] publicKey) {
        if (publicKey != null) {
            this.publicKey = Utils.base64encode(publicKey, true);
        } else {
            this.publicKey = null;
        }
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
        result = prime * result + ((clientKeyID == null) ? 0 : clientKeyID.hashCode());
        result = prime * result + ((keyURL == null) ? 0 : keyURL.hashCode());
        result = prime * result + ((ownerName == null) ? 0 : ownerName.hashCode());
        result = prime * result + ((publicKey == null) ? 0 : publicKey.hashCode());
        result = prime * result + ((realm == null) ? 0 : realm.hashCode());
        result = prime * result + ((size == null) ? 0 : size.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
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
        KeyInfo other = (KeyInfo) obj;
        if (algorithm == null) {
            if (other.algorithm != null)
                return false;
        } else if (!algorithm.equals(other.algorithm))
            return false;
        if (clientKeyID == null) {
            if (other.clientKeyID != null)
                return false;
        } else if (!clientKeyID.equals(other.clientKeyID))
            return false;
        if (keyURL == null) {
            if (other.keyURL != null)
                return false;
        } else if (!keyURL.equals(other.keyURL))
            return false;
        if (ownerName == null) {
            if (other.ownerName != null)
                return false;
        } else if (!ownerName.equals(other.ownerName))
            return false;
        if (publicKey == null) {
            if (other.publicKey != null)
                return false;
        } else if (!publicKey.equals(other.publicKey))
            return false;
        if (realm == null) {
            if (other.realm != null)
                return false;
        } else if (!realm.equals(other.realm))
            return false;
        if (size == null) {
            if (other.size != null)
                return false;
        } else if (!size.equals(other.size))
            return false;
        if (status == null) {
            if (other.status != null)
                return false;
        } else if (!status.equals(other.status))
            return false;
        return true;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.writeValueAsString(this);
    }

    public static KeyInfo fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.readValue(json, KeyInfo.class);
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {

        KeyInfo before = new KeyInfo();
        before.setClientKeyID("key");
        before.setStatus("active");

        String json = before.toJSON();
        System.out.println(json);

        KeyInfo after = KeyInfo.fromJSON(json);
        System.out.println(after.toJSON());
        System.out.println(before.equals(after));
    }
}
