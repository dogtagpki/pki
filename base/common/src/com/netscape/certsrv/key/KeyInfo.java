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

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.cmsutil.util.Utils;

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

}
