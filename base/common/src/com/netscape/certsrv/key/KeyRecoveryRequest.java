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

import com.netscape.certsrv.base.ResourceMessage;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyRecoveryRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyRecoveryRequest extends ResourceMessage {

    private static final String KEY_ID = "keyId";
    private static final String REQUEST_ID = "requestId";
    private static final String TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";
    private static final String SESSION_WRAPPED_PASSPHRASE = "sessionWrappedPassphrase";
    private static final String NONCE_DATA = "nonceData";
    private static final String CERTIFICATE = "certificate";
    private static final String PASSPHRASE = "passphrase";

    public KeyRecoveryRequest() {
        // required for JAXB (defaults)
        setClassName(getClass().getName());
    }

    public KeyRecoveryRequest(MultivaluedMap<String, String> form) {
        if (form.containsKey(KEY_ID)) {
            properties.put(KEY_ID, form.getFirst(KEY_ID));
        }
        if (form.containsKey(REQUEST_ID)) {
            properties.put(REQUEST_ID, form.getFirst(REQUEST_ID));
        }
        properties.put(TRANS_WRAPPED_SESSION_KEY, form.getFirst(TRANS_WRAPPED_SESSION_KEY));
        properties.put(SESSION_WRAPPED_PASSPHRASE, form.getFirst(SESSION_WRAPPED_PASSPHRASE));
        properties.put(NONCE_DATA, form.getFirst(NONCE_DATA));
        properties.put(CERTIFICATE, form.getFirst(CERTIFICATE));
        properties.put(PASSPHRASE, form.getFirst(PASSPHRASE));
        setClassName(getClass().getName());
    }

    public KeyRecoveryRequest(ResourceMessage data) {
        properties.putAll(data.getProperties());
        setClassName(getClass().getName());
    }

    /**
     * @return the keyId
     */
    public KeyId getKeyId() {
        return new KeyId(properties.get(KEY_ID));
    }

    /**
     * @param keyId the keyId to set
     */
    public void setKeyId(KeyId keyId) {
        properties.put(KEY_ID, keyId.toString());
    }

    /**
     * @return the requestId
     */
    public RequestId getRequestId() {
        return new RequestId(properties.get(REQUEST_ID));
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(RequestId requestId) {
        properties.put(REQUEST_ID, requestId.toString());
    }

    /**
     * @return the transWrappedSessionKey
     */
    public String getTransWrappedSessionKey() {
        return properties.get(TRANS_WRAPPED_SESSION_KEY);
    }

    /**
     * @param transWrappedSessionKey the transWrappedSessionKey to set
     */
    public void setTransWrappedSessionKey(String transWrappedSessionKey) {
        properties.put(TRANS_WRAPPED_SESSION_KEY, transWrappedSessionKey);
    }

    /**
     * @return the sessionWrappedPassphrase
     */
    public String getSessionWrappedPassphrase() {
        return properties.get(SESSION_WRAPPED_PASSPHRASE);
    }

    /**
     * @param sessionWrappedPassphrase the sessionWrappedPassphrase to set
     */
    public void setSessionWrappedPassphrase(String sessionWrappedPassphrase) {
        properties.put(SESSION_WRAPPED_PASSPHRASE, sessionWrappedPassphrase);
    }

    /**
     * @return nonceData
     */

    public String getNonceData() {
        return properties.get(NONCE_DATA);
    }

    /**
     * @param nonceData the nonceData to set
     */

    public void setNonceData(String nonceData) {
        properties.put(NONCE_DATA, nonceData);
    }

    /**
     * @return the certificate
     */
    public String getCertificate() {
        return properties.get(CERTIFICATE);
    }

    /**
     * @param certificate the certificate to set
     */
    public void setCertificate(String certificate) {
        properties.put(CERTIFICATE, certificate);
    }

    /**
     * @return the passphrase
     */
    public String getPassphrase() {
        return properties.get(PASSPHRASE);
    }

    /**
     * @param passphrase the passphrase to set
     */
    public void setPassphrase(String passphrase) {
        properties.put(PASSPHRASE, passphrase);
    }


    public static KeyRecoveryRequest valueOf(String string) throws Exception {
        try {
            return ResourceMessage.unmarshal(string, KeyRecoveryRequest.class);
        } catch (Exception e) {
            return null;
        }
    }

    public String toString() {
        try {
            return ResourceMessage.marshal(this, KeyRecoveryRequest.class);
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

        String string = before.toString();
        System.out.println(string);

        KeyRecoveryRequest after = KeyRecoveryRequest.valueOf(string);
        System.out.println(before.equals(after));
    }
}
