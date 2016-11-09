package com.netscape.certsrv.key;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.request.RequestId;
import com.netscape.cmsutil.util.Utils;

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
}
