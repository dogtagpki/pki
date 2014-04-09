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
public class SymKeyGenerationRequest extends ResourceMessage {

    private static final String CLIENT_KEY_ID = "clientKeyID";
    private static final String KEY_SIZE = "keySize";
    private static final String KEY_ALGORITHM = "keyAlgorithm";
    private static final String KEY_USAGE = "keyUsage";
    private static final String TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";

    /* Symmetric Key usages */
    public static final String UWRAP_USAGE = "unwrap";
    public static final String WRAP_USAGE = "wrap";
    public static final String VERIFY_USAGE = "verify";
    public static final String SIGN_USAGE = "sign";
    public static final String DECRYPT_USAGE = "decrypt";
    public static final String ENCRYPT_USAGE = "encrypt";

    public List<String> getUsages() {
        String usageString = attributes.get(KEY_USAGE);
        if (!StringUtils.isBlank(usageString)) {
            return new ArrayList<String>(Arrays.asList(usageString.split(",")));
        }
        return new ArrayList<String>();
    }

    public void setUsages(List<String> usages) {
        attributes.put(KEY_USAGE, StringUtils.join(usages, ","));
    }

    public void addUsage(String usage) {
        List<String> usages = getUsages();
        for (String u : usages) {
            if (u.equals(usage))
                return;
        }
        usages.add(usage);
        setUsages(usages);
    }

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
     * @return the clientKeyId
     */
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
     * @return the keySize
     */
    public Integer getKeySize() {
        try {
            return new Integer(attributes.get(KEY_SIZE));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * @param keySize the key size to set
     */
    public void setKeySize(Integer keySize) {
        attributes.put(KEY_SIZE, keySize.toString());
    }

    /**
     * @return the keyAlgorithm
     */
    public String getKeyAlgorithm() {
        return attributes.get(KEY_ALGORITHM);
    }

    /**
     * @param keyAlgorithm the key algorithm to set
     */
    public void setKeyAlgorithm(String keyAlgorithm) {
        attributes.put(KEY_ALGORITHM, keyAlgorithm);
    }

    /**
     * @return the transWrappedSessionKey
     */
    public String getTransWrappedSessionKey() {
        return attributes.get(TRANS_WRAPPED_SESSION_KEY);
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

        String string = before.toString();
        System.out.println(string);

        SymKeyGenerationRequest after = SymKeyGenerationRequest.valueOf(string);
        System.out.println(before.equals(after));
    }

}
