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

import java.io.StringReader;

import jakarta.ws.rs.core.MultivaluedMap;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.RESTMessage;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class KeyArchivalRequest extends RESTMessage {

    private static final String CLIENT_KEY_ID = "clientKeyID";
    private static final String DATA_TYPE = "dataType";

    // exploded pkiArchiveOptions parameters
    private static final String WRAPPED_PRIVATE_DATA = "wrappedPrivateData";
    private static final String TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";
    private static final String ALGORITHM_OID = "algorithmOID";
    private static final String SYMMETRIC_ALGORITHM_PARAMS = "symmetricAlgorithmParams";

    // parameter for un-exploded pkiArchiveOptions
    private static final String PKI_ARCHIVE_OPTIONS = "pkiArchiveOptions";

    // parameters for symmetric keys
    private static final String KEY_ALGORITHM = "keyAlgorithm";
    private static final String KEY_SIZE = "keySize";

    // parameters to set realm
    private static final String REALM = "realm";

    public KeyArchivalRequest() {
        setClassName(getClass().getName());
    }

    public KeyArchivalRequest(MultivaluedMap<String, String> form) {
        attributes.put(CLIENT_KEY_ID, form.getFirst(CLIENT_KEY_ID));
        attributes.put(DATA_TYPE, form.getFirst(DATA_TYPE));
        attributes.put(WRAPPED_PRIVATE_DATA, form.getFirst(WRAPPED_PRIVATE_DATA));
        attributes.put(KEY_ALGORITHM, form.getFirst(KEY_ALGORITHM));
        attributes.put(KEY_SIZE, form.getFirst(KEY_SIZE));
        attributes.put(PKI_ARCHIVE_OPTIONS, form.getFirst(PKI_ARCHIVE_OPTIONS));
        attributes.put(TRANS_WRAPPED_SESSION_KEY, form.getFirst(TRANS_WRAPPED_SESSION_KEY));
        attributes.put(REALM, form.getFirst(REALM));
        setClassName(getClass().getName());
    }

    public KeyArchivalRequest(RESTMessage data) {
        attributes.putAll(data.getAttributes());
        setClassName(getClass().getName());
    }

    /**
     * @return the clientKeyID
     */
    @JsonIgnore
    public String getClientKeyId() {
        return attributes.get(CLIENT_KEY_ID);
    }

    /**
     * @param clientKeyId the clientKeyId to set
     */
    public void setClientKeyId(String clientKeyId) {
        attributes.put(CLIENT_KEY_ID, clientKeyId);
    }

    /**
     * @return the dataType
     */
    @JsonIgnore
    public String getDataType() {
        return attributes.get(DATA_TYPE);
    }

    /**
     * @param dataType the dataType to set
     */
    public void setDataType(String dataType) {
        attributes.put(DATA_TYPE, dataType);
    }

    /**
     * @return the transWrappedSessionKey
     */
    @JsonIgnore
    public String getTransWrappedSessionKey() {
        return attributes.get(TRANS_WRAPPED_SESSION_KEY);
    }

    /**
     * @param transWrappedSessionKey the trans wrapped session key to set
     */
    public void setTransWrappedSessionKey(String transWrappedSessionKey) {
        attributes.put(TRANS_WRAPPED_SESSION_KEY, transWrappedSessionKey);
    }

    /**
     * @return the PKIArchiveOptions structure
     */
    @JsonIgnore
    public String getPKIArchiveOptions() {
        return attributes.get(PKI_ARCHIVE_OPTIONS);
    }

    /**
     * @param pkiArchiveOptions the archive options structure to set
     */
    public void setPKIArchiveOptions(String pkiArchiveOptions) {
        attributes.put(PKI_ARCHIVE_OPTIONS, pkiArchiveOptions);
    }

    /**
     * @return the algorithm OID structure
     */
    @JsonIgnore
    public String getAlgorithmOID() {
        return attributes.get(ALGORITHM_OID);
    }

    /**
     * @param algorithmOID the symmetric algorithm OID to set
     */
    public void setAlgorithmOID(String algorithmOID) {
        attributes.put(ALGORITHM_OID, algorithmOID);
    }

    /**
     * @return the algorithm params structure
     */
    @JsonIgnore
    public String getSymmetricAlgorithmParams() {
        return attributes.get(SYMMETRIC_ALGORITHM_PARAMS);
    }

    /**
     * @param params the algorithm params to set
     */
    public void setSymmetricAlgorithmParams(String params) {
        attributes.put(SYMMETRIC_ALGORITHM_PARAMS, params);
    }

    /**
     * @return the pkiArchiveOptions structure
     */
    @JsonIgnore
    public String getWrappedPrivateData() {
        return attributes.get(WRAPPED_PRIVATE_DATA);
    }

    /**
     * @param wrappedPrivateData the wrappedPrivateData to set
     */
    public void setWrappedPrivateData(String wrappedPrivateData) {
        attributes.put(WRAPPED_PRIVATE_DATA, wrappedPrivateData);
    }

    /**
     * @return the keyAlgorithm (valid for symmetric keys)
     */
    @JsonIgnore
    public String getKeyAlgorithm() {
        return attributes.get(KEY_ALGORITHM);
    }

    /**
     * @param algorithm the key algorithm to set (valid for symmetric keys)
     */
    public void setKeyAlgorithm(String algorithm) {
        attributes.put(KEY_ALGORITHM, algorithm);
    }

    /**
     * @return the key strength (valid for symmetric keys)
     */
    @JsonIgnore
    public Integer getKeySize() {
        String keySize = attributes.get(KEY_SIZE);
        return keySize == null ? null : Integer.valueOf(keySize);
    }

    /**
     * @param keySize the key strength to set (valid for symmetric keys)
     */
    public void setKeySize(Integer keySize) {
        if (keySize == null) return;
        attributes.put(KEY_SIZE, Integer.toString(keySize));
    }

    /**
     * @return the authentication realm
     */
    @JsonIgnore
    public String getRealm() {
        return attributes.get(REALM);
    }

    /**
     * @param realm - the authentication realm
     */
    public void setRealm(String realm) {
        if (realm != null) {
            attributes.put(REALM, realm);
        } else {
            attributes.remove(REALM);
        }
    }

    @Override
    public Element toDOM(Document document) {
        Element element = document.createElement("KeyArchivalRequest");
        toDOM(document, element);
        return element;
    }

    public static KeyArchivalRequest fromDOM(Element element) {
        KeyArchivalRequest request = new KeyArchivalRequest();
        fromDOM(element, request);
        return request;
    }

    public static KeyArchivalRequest fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
