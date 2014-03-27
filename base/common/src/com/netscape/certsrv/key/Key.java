package com.netscape.certsrv.key;

import com.netscape.cmsutil.util.Utils;

/**
 * Represents a Key stored in the DRM.
 * Return type for all the key retrieval requests of
 * the KeyClient.
 *
 * @author akoneru
 *
 */
public class Key {

    private byte[] encryptedData;

    private byte[] nonceData;

    private String p12Data;

    private String algorithm;

    private Integer size;

    private byte[] data;

    public Key() {
        super();
    }

    public Key(KeyData data) {
        encryptedData = Utils.base64decode(data.getWrappedPrivateData());
        nonceData = Utils.base64decode(data.getNonceData());
        p12Data = data.getP12Data();
        algorithm = data.getAlgorithm();
        size = data.getSize();
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

}
