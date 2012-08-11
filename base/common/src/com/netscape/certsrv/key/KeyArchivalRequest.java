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

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyArchivalRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyArchivalRequest {

    private static final String CLIENT_ID = "clientID";
    private static final String TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";
    private static final String DATA_TYPE = "dataType";
    private static final String WRAPPED_PRIVATE_DATA = "wrappedPrivateData";

    @XmlElement
    protected String clientId;

    @XmlElement
    protected String transWrappedSessionKey;

    @XmlElement
    protected String dataType;

    @XmlElement
    protected String wrappedPrivateData;

    public KeyArchivalRequest() {
        // required for JAXB (defaults)
    }

    public KeyArchivalRequest(MultivaluedMap<String, String> form) {
        clientId = form.getFirst(CLIENT_ID);
        transWrappedSessionKey = form.getFirst(TRANS_WRAPPED_SESSION_KEY);
        dataType = form.getFirst(DATA_TYPE);
        wrappedPrivateData = form.getFirst(WRAPPED_PRIVATE_DATA);
    }

    /**
     * @return the clientId
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * @param clientId the clientId to set
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * @return the transWrappedSessionKey
     */
    public String getTransWrappedSessionKey() {
        return transWrappedSessionKey;
    }

    /**
     * @param transWrappedSessionKey the transWrappedSessionKey to set
     */
    public void setTransWrappedSessionKey(String transWrappedSessionKey) {
        this.transWrappedSessionKey = transWrappedSessionKey;
    }

    /**
     * @return the dataType
     */
    public String getDataType() {
        return dataType;
    }

    /**
     * @param dataType the dataType to set
     */
    public void setDataType(String dataType) {
        this.dataType = dataType;
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


}
