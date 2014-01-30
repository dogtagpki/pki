package com.netscape.certsrv.key;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.crypto.KeyGenAlgorithm;

import com.netscape.certsrv.base.ResourceMessage;

/**
 * @author alee
 *
 */
@XmlRootElement(name="SymKeyGenerationRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class SymKeyGenerationRequest extends ResourceMessage {

    private static final String CLIENT_ID = "clientID";
    private static final String KEY_SIZE = "keySize";
    private static final String KEY_ALGORITHM = "keyAlgorithm";
    private static final String KEY_USAGE = "keyUsage";

    /* Symmetric Key usages */
    public static final String UWRAP_USAGE = "unwrap";
    public static final String WRAP_USAGE = "wrap";
    public static final String VERIFY_USAGE = "verify";
    public static final String SIGN_USAGE = "sign";
    public static final String DECRYPT_USAGE = "decrypt";
    public static final String ENCRYPT_USAGE = "encrypt";

    public static final Map<String, KeyGenAlgorithm> KEYGEN_ALGORITHMS;
    static {
        KEYGEN_ALGORITHMS = new HashMap<String, KeyGenAlgorithm>();
        KEYGEN_ALGORITHMS.put("DES", KeyGenAlgorithm.DES);
        KEYGEN_ALGORITHMS.put("DESede", KeyGenAlgorithm.DESede);
        KEYGEN_ALGORITHMS.put("DES3", KeyGenAlgorithm.DES3);
        KEYGEN_ALGORITHMS.put("RC2", KeyGenAlgorithm.RC2);
        KEYGEN_ALGORITHMS.put("RC4", KeyGenAlgorithm.RC4);
        KEYGEN_ALGORITHMS.put("AES", KeyGenAlgorithm.AES);
    }

    public List<String> getUsages() {
        String usageString = properties.get(KEY_USAGE);
        if (! StringUtils.isBlank(usageString)) {
            return new ArrayList<String>(Arrays.asList(usageString.split(",")));
        }
        return new ArrayList<String>();
    }

    public void setUsages(List<String> usages) {
        properties.put(KEY_USAGE, StringUtils.join(usages, ","));
    }

    public void addUsage(String usage) {
        List<String> usages = getUsages();
        for (String u: usages) {
            if (u.equals(usage)) return;
        }
        usages.add(usage);
        setUsages(usages);
    }

    public SymKeyGenerationRequest() {
        // required for JAXB (defaults)
        setClassName(getClass().getName());
    }

    public SymKeyGenerationRequest(MultivaluedMap<String, String> form) {
        properties.put(CLIENT_ID, form.getFirst(CLIENT_ID));
        properties.put(KEY_SIZE, form.getFirst(KEY_SIZE));
        properties.put(KEY_ALGORITHM, form.getFirst(KEY_ALGORITHM));
        properties.put(KEY_USAGE, form.getFirst(KEY_USAGE));

        String usageString = properties.get(KEY_USAGE);
        if (! StringUtils.isBlank(usageString)) {
            setUsages(new ArrayList<String>(Arrays.asList(usageString.split(","))));
        }
        setClassName(getClass().getName());
    }

    public SymKeyGenerationRequest(ResourceMessage data) {
        properties.putAll(data.getProperties());
        setClassName(getClass().getName());
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
        properties.put(CLIENT_ID, clientId);
    }

    /**
     * @return the keySize
     */
    public int getKeySize() {
        return Integer.parseInt(properties.get(KEY_SIZE));
    }

    /**
     * @param keySize the key size to set
     */
    public void setKeySize(int keySize) {
        properties.put(KEY_SIZE, Integer.toString(keySize));
    }

    /**
     * @return the keyAlgorithm
     */
    public String getKeyAlgorithm() {
        return properties.get(KEY_ALGORITHM);
    }

    /**
     * @param keyAlgorithm the key algorithm to set
     */
    public void setKeyAlgorithm(String keyAlgorithm) {
        properties.put(KEY_ALGORITHM, keyAlgorithm);
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

    public static void main(String args[]) throws Exception {

        SymKeyGenerationRequest before = new SymKeyGenerationRequest();
        before.setClientId("vek 12345");
        before.setKeyAlgorithm("AES");
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
