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

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyArchivalRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyArchivalRequest extends ResourceMessage {

    private static final String CLIENT_ID = "clientID";
    private static final String DATA_TYPE = "dataType";
    private static final String WRAPPED_PRIVATE_DATA = "wrappedPrivateData";

    public KeyArchivalRequest() {
        // required for JAXB (defaults)
        setClassName(getClass().getName());
    }

    public KeyArchivalRequest(MultivaluedMap<String, String> form) {
        attributes.put(CLIENT_ID, form.getFirst(CLIENT_ID));
        attributes.put(DATA_TYPE, form.getFirst(DATA_TYPE));
        attributes.put(WRAPPED_PRIVATE_DATA, form.getFirst(WRAPPED_PRIVATE_DATA));
        setClassName(getClass().getName());
    }

    public KeyArchivalRequest(ResourceMessage data) {
        attributes.putAll(data.getAttributes());
        setClassName(getClass().getName());
    }

    /**
     * @return the clientId
     */
    public String getClientId() {
        return attributes.get(CLIENT_ID);
    }

    /**
     * @param clientId the clientId to set
     */
    public void setClientId(String clientId) {
        attributes.put(CLIENT_ID, clientId);
    }

    /**
     * @return the dataType
     */
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
     * @return the wrappedPrivateData
     */
    public String getWrappedPrivateData() {
        return attributes.get(WRAPPED_PRIVATE_DATA);
    }

    /**
     * @param wrappedPrivateData the wrappedPrivateData to set
     */
    public void setWrappedPrivateData(String wrappedPrivateData) {
        attributes.put(WRAPPED_PRIVATE_DATA, wrappedPrivateData);
    }

    public String toString() {
        try {
            return ResourceMessage.marshal(this, KeyArchivalRequest.class);
        } catch (Exception e) {
            return super.toString();
        }
    }

    public static KeyArchivalRequest valueOf(String string) throws Exception {
        try {
            return ResourceMessage.unmarshal(string, KeyArchivalRequest.class);
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        KeyArchivalRequest before = new KeyArchivalRequest();
        before.setClientId("vek 12345");
        before.setDataType(KeyRequestResource.SYMMETRIC_KEY_TYPE);
        before.setWrappedPrivateData("XXXXABCDEFXXX");

        String string = before.toString();
        System.out.println(string);

        KeyArchivalRequest after = KeyArchivalRequest.valueOf(string);
        System.out.println(before.equals(after));
    }

}
