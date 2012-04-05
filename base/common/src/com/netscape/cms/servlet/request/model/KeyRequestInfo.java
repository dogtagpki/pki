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

package com.netscape.cms.servlet.request.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;

@XmlRootElement(name="SecurityDataRequestInfo")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyRequestInfo {

    @XmlElement
    protected String requestType;

    @XmlElement
    protected String requestStatus;

    @XmlElement
    protected String requestURL;

    @XmlElement
    protected String keyURL;

    public KeyRequestInfo(){
        // required to be here for JAXB (defaults)
    }

    /**
     * @return the requestType
     */
    public String getRequestType() {
        return requestType;
    }

    /**
     * @param requestType the requestType to set
     */
    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    /**
     * @return the requestStatus
     */
    public String getRequestStatus() {
        return requestStatus;
    }

    /**
     * @param requestStatus the requestStatus to set
     */
    public void setRequestStatus(String requestStatus) {
        this.requestStatus = requestStatus;
    }

    /**
     * @return the requestURL
     */
    public String getRequestURL() {
        return requestURL;
    }

    /**
     * @return the request ID in the requestURL
     */
    public RequestId getRequestId() {
        String id = requestURL.substring(requestURL.lastIndexOf("/") + 1);
        return new RequestId(id);
    }

    /**
     * @param requestURL the requestURL to set
     */
    public void setRequestURL(String requestURL) {
        this.requestURL = requestURL;
    }

    /**
     * @return the keyURL
     */
    public String getKeyURL() {
        return keyURL;
    }

    /**
     * @return the key ID in the keyURL
     */
    public KeyId getKeyId() {
        String id = keyURL.substring(keyURL.lastIndexOf("/") + 1);
        return new KeyId(id);
    }

    /**
     * @param keyURL the keyURL to set
     */
    public void setKeyURL(String keyURL) {
        this.keyURL = keyURL;
    }
}
