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
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.dbs.keydb.KeyIdAdapter;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestIdAdapter;

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyRecoveryRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyRecoveryRequest {

    private static final String KEY_ID = "keyId";
    private static final String REQUEST_ID = "requestId";
    private static final String TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";
    private static final String SESSION_WRAPPED_PASSPHRASE = "sessionWrappedPassphrase";
    private static final String NONCE_DATA = "nonceData";

    @XmlElement
    @XmlJavaTypeAdapter(KeyIdAdapter.class)
    protected KeyId keyId;

    @XmlElement
    @XmlJavaTypeAdapter(RequestIdAdapter.class)
    protected RequestId requestId;

    @XmlElement
    protected String transWrappedSessionKey;

    @XmlElement
    protected String sessionWrappedPassphrase;

    @XmlElement
    protected String nonceData;

    @XmlElement
    protected String certificate;

    @XmlElement
    protected String passphrase;

    public KeyRecoveryRequest() {
        // required for JAXB (defaults)
    }

    public KeyRecoveryRequest(MultivaluedMap<String, String> form) {
        if (form.containsKey(KEY_ID)) {
            keyId = new KeyId(form.getFirst(KEY_ID));
        }
        if (form.containsKey(REQUEST_ID)) {
            requestId = new RequestId(form.getFirst(REQUEST_ID));
        }
        transWrappedSessionKey = form.getFirst(TRANS_WRAPPED_SESSION_KEY);
        sessionWrappedPassphrase = form.getFirst(SESSION_WRAPPED_PASSPHRASE);
        nonceData = form.getFirst(NONCE_DATA);
    }

    /**
     * @return the keyId
     */
    public KeyId getKeyId() {
        return keyId;
    }

    /**
     * @param keyId the keyId to set
     */
    public void setKeyId(KeyId keyId) {
        this.keyId = keyId;
    }

    /**
     * @return the requestId
     */
    public RequestId getRequestId() {
        return requestId;
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(RequestId requestId) {
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

    /**
     * @return nonceData
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
     * @return the certificate
     */
    public String getCertificate() {
        return certificate;
    }

    /**
     * @param certificate the certificate to set
     */
    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    /**
     * @return the passphrase
     */
    public String getPassphrase() {
        return passphrase;
    }

    /**
     * @param passphrase the passphrase to set
     */
    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }
}
