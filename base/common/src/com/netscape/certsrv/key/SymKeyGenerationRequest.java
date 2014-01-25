package com.netscape.certsrv.key;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="SymKeyGenerationRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class SymKeyGenerationRequest extends KeyRequest {

    private static final String CLIENT_ID = "clientID";
    private static final String DATA_TYPE = "dataType";

    public SymKeyGenerationRequest() {
        // required for JAXB (defaults)
    }

    public SymKeyGenerationRequest(MultivaluedMap<String, String> form) {
        this.properties.put(CLIENT_ID, form.getFirst(CLIENT_ID));
        this.properties.put(DATA_TYPE, form.getFirst(DATA_TYPE));
    }

    /**
     * @return the clientId
     */
    public String getClientId() {
        return properties.get(CLIENT_ID);
    }

    /**
     * @param clientId the clientId to set
     */
    public void setClientId(String clientId) {
        this.properties.put(CLIENT_ID, clientId);
    }

    /**
     * @return the dataType
     */
    public String getDataType() {
        return this.properties.get(DATA_TYPE);
    }

    /**
     * @param dataType the dataType to set
     */
    public void setDataType(String dataType) {
        this.properties.put(DATA_TYPE, dataType);
    }

    public String toString() {
        try {
            return KeyRequest.marshal(this, SymKeyGenerationRequest.class);
        } catch (Exception e) {
            return super.toString();
        }
    }

    public static SymKeyGenerationRequest valueOf(String string) throws Exception {
        try {
            return KeyRequest.unmarshal(string, SymKeyGenerationRequest.class);
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        SymKeyGenerationRequest before = new SymKeyGenerationRequest();
        before.setClientId("vek 12345");
        before.setDataType(KeyRequestResource.SYMMETRIC_KEY_TYPE);
        before.setRequestType(KeyRequestResource.KEY_GENERATION_REQUEST);

        String string = before.toString();
        System.out.println(string);

        SymKeyGenerationRequest after = SymKeyGenerationRequest.valueOf(string);
        System.out.println(before.equals(after));
    }

}
