package com.netscape.certsrv.key;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.mozilla.jss.netscape.security.util.Utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Represents a Key stored in the DRM.
 * Return type for all the key retrieval requests of
 * the KeyClient.
 *
 * @author akoneru
 *
 */
@XmlRootElement(name="Key")
@XmlAccessorType(XmlAccessType.NONE)
public class Key {

    @XmlElement
    private byte[] encryptedData;

    @XmlElement
    private byte[] nonceData;

    @XmlElement
    private String p12Data;

    @XmlElement
    private String algorithm;

    @XmlElement
    private Integer size;

    @XmlElement
    private byte[] data;

    @XmlElement
    private RequestId requestId;

    @XmlElement
    private String wrapAlgorithm;

    @XmlElement
    private String encryptAlgorithmOID;

    @XmlElement
    private String type;

    @XmlElement
    private String publicKey;

    public Key() {
        super();
    }

    public Key(KeyData data) {
        if (data.getWrappedPrivateData() != null)
            encryptedData = Utils.base64decode(data.getWrappedPrivateData());
        if (data.getNonceData() != null)
            nonceData = Utils.base64decode(data.getNonceData());
        p12Data = data.getP12Data();
        algorithm = data.getAlgorithm();
        size = data.getSize();
        requestId = data.requestID;
        wrapAlgorithm = data.getWrapAlgorithm();
        encryptAlgorithmOID = data.getEncryptAlgorithmOID();
        type = data.getType();
        publicKey = data.getPublicKey();
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }

    public byte[] getNonceData() {
        return nonceData;
    }

    public void setNonceData(byte[] nonceData) {
        this.nonceData = nonceData;
    }

    public String getP12Data() {
        return p12Data;
    }

    public void setP12Data(String p12Data) {
        this.p12Data = p12Data;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public RequestId getRequestId() {
        return requestId;
    }

    public void setRequestId(RequestId requestId) {
        this.requestId = requestId;
    }

    public String getWrapAlgorithm() {
        return wrapAlgorithm;
    }

    public void setWrapAlgorithm(String wrapAlgorithm) {
        this.wrapAlgorithm = wrapAlgorithm;
    }

    public String getEncryptAlgorithmOID() {
        return encryptAlgorithmOID;
    }

    public void setEncryptAlgorithmOID(String encryptAlgorithmOID) {
        this.encryptAlgorithmOID = encryptAlgorithmOID;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public void clearSensitiveData() {
        CryptoUtil.obscureBytes(data, "random");
        data = null;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(Key.class).createMarshaller();
        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static Key fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(Key.class).createUnmarshaller();
        return (Key) unmarshaller.unmarshal(new StringReader(xml));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.writeValueAsString(this);
    }

    public static Key fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.readValue(json, Key.class);
    }

    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
