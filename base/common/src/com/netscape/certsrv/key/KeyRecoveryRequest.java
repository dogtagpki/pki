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
            attributes.put(KEY_ID, form.getFirst(KEY_ID));
        }
        if (form.containsKey(REQUEST_ID)) {
            attributes.put(REQUEST_ID, form.getFirst(REQUEST_ID));
        }
        attributes.put(TRANS_WRAPPED_SESSION_KEY, form.getFirst(TRANS_WRAPPED_SESSION_KEY));
        attributes.put(SESSION_WRAPPED_PASSPHRASE, form.getFirst(SESSION_WRAPPED_PASSPHRASE));
        attributes.put(NONCE_DATA, form.getFirst(NONCE_DATA));
        attributes.put(CERTIFICATE, form.getFirst(CERTIFICATE));
        attributes.put(PASSPHRASE, form.getFirst(PASSPHRASE));
        setClassName(getClass().getName());
    }

    public KeyRecoveryRequest(ResourceMessage data) {
        attributes.putAll(data.getAttributes());
        setClassName(getClass().getName());
    }

    /**
     * @return the keyId
     */
    public KeyId getKeyId() {
        String id = attributes.get(KEY_ID);
        if (id != null)
            return new KeyId(attributes.get(KEY_ID));
        return null;
    }

    /**
     * @param keyId the keyId to set
     */
    public void setKeyId(KeyId keyId) {
        attributes.put(KEY_ID, keyId.toString());
    }

    /**
     * @return the requestId
     */
    public RequestId getRequestId() {
        String id = attributes.get(REQUEST_ID);
        if (id != null)
            return new RequestId(attributes.get(REQUEST_ID));
        return null;
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(RequestId requestId) {
        attributes.put(REQUEST_ID, requestId.toString());
    }

    /**
     * @return the transWrappedSessionKey
     */
    public String getTransWrappedSessionKey() {
        return attributes.get(TRANS_WRAPPED_SESSION_KEY);
    }

    /**
     * @param transWrappedSessionKey the transWrappedSessionKey to set
     */
    public void setTransWrappedSessionKey(String transWrappedSessionKey) {
        attributes.put(TRANS_WRAPPED_SESSION_KEY, transWrappedSessionKey);
    }

    /**
     * @return the sessionWrappedPassphrase
     */
    public String getSessionWrappedPassphrase() {
        return attributes.get(SESSION_WRAPPED_PASSPHRASE);
    }

    /**
     * @param sessionWrappedPassphrase the sessionWrappedPassphrase to set
     */
    public void setSessionWrappedPassphrase(String sessionWrappedPassphrase) {
        attributes.put(SESSION_WRAPPED_PASSPHRASE, sessionWrappedPassphrase);
    }

    /**
     * @return nonceData
     */

    public String getNonceData() {
        return attributes.get(NONCE_DATA);
    }

    /**
     * @param nonceData the nonceData to set
     */

    public void setNonceData(String nonceData) {
        attributes.put(NONCE_DATA, nonceData);
    }

    /**
     * @return the certificate
     */
    public String getCertificate() {
        return attributes.get(CERTIFICATE);
    }

    /**
     * @param certificate the certificate to set
     */
    public void setCertificate(String certificate) {
        attributes.put(CERTIFICATE, certificate);
    }

    /**
     * @return the passphrase
     */
    public String getPassphrase() {
        return attributes.get(PASSPHRASE);
    }

    /**
     * @param passphrase the passphrase to set
     */
    public void setPassphrase(String passphrase) {
        attributes.put(PASSPHRASE, passphrase);
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
