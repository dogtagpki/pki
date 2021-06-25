package com.netscape.certsrv.key;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.ResourceMessage;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "SymKeyGenerationRequest")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
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
            setUsages(new ArrayList<>(Arrays.asList(usageString.split(","))));
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
    @Override
    public void setTransWrappedSessionKey(String transWrappedSessionKey) {
        attributes.put(TRANS_WRAPPED_SESSION_KEY, transWrappedSessionKey);
    }

    @Override
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
        List<String> list = new ArrayList<>();
        list.add(WRAP_USAGE);
        list.add(UWRAP_USAGE);
        list.add(DECRYPT_USAGE);
        list.add(ENCRYPT_USAGE);
        list.add(VERIFY_USAGE);
        list.add(SIGN_USAGE);

        return list;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(SymKeyGenerationRequest.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static SymKeyGenerationRequest fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(SymKeyGenerationRequest.class).createUnmarshaller();
        return (SymKeyGenerationRequest) unmarshaller.unmarshal(new StringReader(xml));
    }

}
