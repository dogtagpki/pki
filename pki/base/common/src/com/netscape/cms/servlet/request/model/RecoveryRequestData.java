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
package com.netscape.cms.servlet.request.model;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="SecurityDataRecoveryRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class RecoveryRequestData {
    
    private static final String KEY_ID = "keyId";
    private static final String REQUEST_ID = "requestId";
    private static final String TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";
    private static final String SESSION_WRAPPED_PASSPHRASE = "sessionWrappedPassphrase";

    @XmlElement
    protected String keyId;
    
    @XmlElement
    protected String requestId;
    
    @XmlElement
    protected String transWrappedSessionKey;
    
    @XmlElement
    protected String sessionWrappedPassphrase;
    
    public RecoveryRequestData() {
        // required for JAXB (defaults)
    }
    
    public RecoveryRequestData(MultivaluedMap<String, String> form) {
        keyId = form.getFirst(KEY_ID);
        requestId = form.getFirst(REQUEST_ID);
        transWrappedSessionKey = form.getFirst(TRANS_WRAPPED_SESSION_KEY);
        sessionWrappedPassphrase = form.getFirst(SESSION_WRAPPED_PASSPHRASE);
    }

    /**
     * @return the keyId
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * @param keyId the keyId to set
     */
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * @return the requestId
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(String requestId) {
        this.requestId = requestId;
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
     * @return the sessionWrappedPassphrase
     */
    public String getSessionWrappedPassphrase() {
        return sessionWrappedPassphrase;
    }

    /**
     * @param sessionWrappedPassphrase the sessionWrappedPassphrase to set
     */
    public void setSessionWrappedPassphrase(String sessionWrappedPassphrase) {
        this.sessionWrappedPassphrase = sessionWrappedPassphrase;
    }

}
