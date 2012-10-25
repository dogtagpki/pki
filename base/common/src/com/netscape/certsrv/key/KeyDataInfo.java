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

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyDataInfo")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyDataInfo {

    @XmlElement
    protected String keyURL;

    @XmlElement
    protected String clientID;

    @XmlElement
    protected String status;

    @XmlElement
    protected String algorithm;

    @XmlElement
    protected Integer size;

    @XmlElement
    protected String ownerName;

    public KeyDataInfo() {
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
     * @return the clientID
     */
    public String getClientID() {
        return clientID;
    }

    /**
     * @param clientID the clientID to set
     */
    public void setClientID(String clientID) {
        this.clientID = clientID;
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
}
