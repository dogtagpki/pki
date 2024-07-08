package com.netscape.certsrv.key;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.ws.rs.core.MultivaluedMap;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

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
public class SymKeyGenerationRequest extends KeyGenerationRequest {

    /* Symmetric Key usages */
    public static final String UWRAP_USAGE = "unwrap";
    public static final String WRAP_USAGE = "wrap";
    public static final String VERIFY_USAGE = "verify";
    public static final String SIGN_USAGE = "sign";
    public static final String DECRYPT_USAGE = "decrypt";
    public static final String ENCRYPT_USAGE = "encrypt";

    public SymKeyGenerationRequest() {
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

    public SymKeyGenerationRequest(RESTMessage data) {
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
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
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

    @Override
    public Element toDOM(Document document) {
        Element element = document.createElement("SymKeyGenerationRequest");
        toDOM(document, element);
        return element;
    }

    public static SymKeyGenerationRequest fromDOM(Element element) {
        SymKeyGenerationRequest request = new SymKeyGenerationRequest();
        fromDOM(element, request);
        return request;
    }

    public static SymKeyGenerationRequest fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
