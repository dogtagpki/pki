package com.netscape.certsrv.key;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.base.ResourceMessage;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "SymKeyGenerationRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class SymKeyGenerationRequest extends KeyGenerationRequest {

    /* Symmetric Key usages */
    public static final String UWRAP_USAGE = "unwrap";
    public static final String WRAP_USAGE = "wrap";
    public static final String VERIFY_USAGE = "verify";
    public static final String SIGN_USAGE = "sign";
    public static final String DECRYPT_USAGE = "decrypt";
    public static final String ENCRYPT_USAGE = "encrypt";

    public SymKeyGenerationRequest() {
        // required for JAXB (defaults)
        setClassName(getClass().getName());
    }

    public SymKeyGenerationRequest(MultivaluedMap<String, String> form) {
        attributes.put(CLIENT_KEY_ID, form.getFirst(CLIENT_KEY_ID));
        attributes.put(KEY_SIZE, form.getFirst(KEY_SIZE));
        attributes.put(KEY_ALGORITHM, form.getFirst(KEY_ALGORITHM));
        attributes.put(KEY_USAGE, form.getFirst(KEY_USAGE));
        attributes.put(TRANS_WRAPPED_SESSION_KEY, form.getFirst(TRANS_WRAPPED_SESSION_KEY));
        attributes.put(REALM, form.getFirst(REALM));

        String usageString = attributes.get(KEY_USAGE);
        if (!StringUtils.isBlank(usageString)) {
            setUsages(new ArrayList<String>(Arrays.asList(usageString.split(","))));
        }
        setClassName(getClass().getName());
    }

    public SymKeyGenerationRequest(ResourceMessage data) {
        attributes.putAll(data.getAttributes());
        setClassName(getClass().getName());
    }

    /**
     * @param transWrappedSessionKey the wrapped seesion key to set
     */
    public void setTransWrappedSessionKey(String transWrappedSessionKey) {
        attributes.put(TRANS_WRAPPED_SESSION_KEY, transWrappedSessionKey);
    }

    public String toString() {
        try {
            return ResourceMessage.marshal(this, SymKeyGenerationRequest.class);
        } catch (Exception e) {
            return super.toString();
        }
    }

    public static SymKeyGenerationRequest valueOf(String string) throws Exception {
        try {
            return ResourceMessage.unmarshal(string, SymKeyGenerationRequest.class);
        } catch (Exception e) {
            return null;
        }
    }

    public static List<String> getValidUsagesList() {
        List<String> list = new ArrayList<String>();
        list.add(WRAP_USAGE);
        list.add(UWRAP_USAGE);
        list.add(DECRYPT_USAGE);
        list.add(ENCRYPT_USAGE);
        list.add(KEY_USAGE);
        list.add(SIGN_USAGE);

        return list;
    }

    public static void main(String args[]) throws Exception {

        SymKeyGenerationRequest before = new SymKeyGenerationRequest();
        before.setClientKeyId("vek 12345");
        before.setKeyAlgorithm(KeyRequestResource.AES_ALGORITHM);
        before.setKeySize(128);
        before.addUsage(SymKeyGenerationRequest.DECRYPT_USAGE);
        before.addUsage(SymKeyGenerationRequest.ENCRYPT_USAGE);
        before.addUsage(SymKeyGenerationRequest.SIGN_USAGE);
        before.setRealm("ipa");

        String string = before.toString();
        System.out.println(string);

        SymKeyGenerationRequest after = SymKeyGenerationRequest.valueOf(string);
        System.out.println(before.equals(after));
    }

}
