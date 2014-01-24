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
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyRecoveryRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyRecoveryRequest extends Request {

    private static final String KEY_ID = "keyId";
    private static final String REQUEST_ID = "requestId";
    private static final String TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";
    private static final String SESSION_WRAPPED_PASSPHRASE = "sessionWrappedPassphrase";
    private static final String NONCE_DATA = "nonceData";
    private static final String CERTIFICATE = "certificate";
    private static final String PASSPHRASE = "passphrase";

    public KeyRecoveryRequest() {
        // required for JAXB (defaults)
    }

    public KeyRecoveryRequest(MultivaluedMap<String, String> form) {
        if (form.containsKey(KEY_ID)) {
            this.properties.put(KEY_ID, form.getFirst(KEY_ID));
        }
        if (form.containsKey(REQUEST_ID)) {
            this.properties.put(REQUEST_ID, form.getFirst(REQUEST_ID));
        }
        this.properties.put(TRANS_WRAPPED_SESSION_KEY, form.getFirst(TRANS_WRAPPED_SESSION_KEY));
        this.properties.put(SESSION_WRAPPED_PASSPHRASE, form.getFirst(SESSION_WRAPPED_PASSPHRASE));
        this.properties.put(NONCE_DATA, form.getFirst(NONCE_DATA));
        this.properties.put(CERTIFICATE, form.getFirst(CERTIFICATE));
        this.properties.put(PASSPHRASE, form.getFirst(PASSPHRASE));

    }

    /**
     * @return the keyId
     */
    public KeyId getKeyId() {
        return new KeyId(this.properties.get(KEY_ID));
    }

    /**
     * @param keyId the keyId to set
     */
    public void setKeyId(KeyId keyId) {
        this.properties.put(KEY_ID, keyId.toString());
    }

    /**
     * @return the requestId
     */
    public RequestId getRequestId() {
        return new RequestId(this.properties.get(REQUEST_ID));
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(RequestId requestId) {
        this.properties.put(REQUEST_ID, requestId.toString());
    }

    /**
     * @return the transWrappedSessionKey
     */
    public String getTransWrappedSessionKey() {
        return this.properties.get(TRANS_WRAPPED_SESSION_KEY);
    }

    /**
     * @param transWrappedSessionKey the transWrappedSessionKey to set
     */
    public void setTransWrappedSessionKey(String transWrappedSessionKey) {
        this.properties.put(TRANS_WRAPPED_SESSION_KEY, transWrappedSessionKey);
    }

    /**
     * @return the sessionWrappedPassphrase
     */
    public String getSessionWrappedPassphrase() {
        return this.properties.get(SESSION_WRAPPED_PASSPHRASE);
    }

    /**
     * @param sessionWrappedPassphrase the sessionWrappedPassphrase to set
     */
    public void setSessionWrappedPassphrase(String sessionWrappedPassphrase) {
        this.properties.put(SESSION_WRAPPED_PASSPHRASE, sessionWrappedPassphrase);
    }

    /**
     * @return nonceData
     */

    public String getNonceData() {
        return this.properties.get(NONCE_DATA);
    }

    /**
     * @param nonceData the nonceData to set
     */

    public void setNonceData(String nonceData) {
        this.properties.put(NONCE_DATA, nonceData);
    }

    /**
     * @return the certificate
     */
    public String getCertificate() {
        return this.properties.get(CERTIFICATE);
    }

    /**
     * @param certificate the certificate to set
     */
    public void setCertificate(String certificate) {
        this.properties.put(CERTIFICATE, certificate);
    }

    /**
     * @return the passphrase
     */
    public String getPassphrase() {
        return this.properties.get(PASSPHRASE);
    }

    /**
     * @param passphrase the passphrase to set
     */
    public void setPassphrase(String passphrase) {
        this.properties.put(PASSPHRASE, passphrase);
    }


    public static KeyRecoveryRequest valueOf(String string) throws Exception {
        try {
            return Request.unmarshal(string, KeyRecoveryRequest.class);
        } catch (Exception e) {
            return null;
        }
    }

    public String toString() {
        try {
            return Request.marshal(this, KeyRecoveryRequest.class);
        } catch (Exception e) {
            return super.toString();
        }
    }

    public static void main(String args[]) throws Exception {

        KeyRecoveryRequest before = new KeyRecoveryRequest();
        before.setKeyId(new KeyId("0x123456"));
        before.setNonceData("nonce-XXX12345");
        before.setPassphrase("password");
        before.setRequestId(new RequestId("0x123F"));
        before.setCertificate("123ABCAAAA");
        before.setSessionWrappedPassphrase("XXXXXXXX1234");
        before.setTransWrappedSessionKey("124355AAA");
        before.setRequestType(KeyRequestResource.RECOVERY_REQUEST);

        String string = before.toString();
        System.out.println(string);

        KeyRecoveryRequest after = KeyRecoveryRequest.valueOf(string);
        System.out.println(before.equals(after));
    }
}
