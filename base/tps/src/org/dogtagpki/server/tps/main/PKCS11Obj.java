package org.dogtagpki.server.tps.main;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.main.Util;

import sun.security.pkcs11.wrapper.PKCS11Constants;

import com.netscape.certsrv.apps.CMS;

public class PKCS11Obj {

    private ArrayList<ObjectSpec> objectSpecs;

    public PKCS11Obj() {
        objectSpecs = new ArrayList<ObjectSpec>();
    }

    private int oldFormatVersion;
    private int oldObjectVersion;

    private int formatVersion;
    private int objectVersion;

    private TPSBuffer tokenName;
    private TPSBuffer cuid;

    public static PKCS11Obj parse(TPSBuffer b, int offset) throws TPSException, DataFormatException, IOException
    {
        PKCS11Obj o = new PKCS11Obj();

        int formatVersion = b.getIntFrom2Bytes(0);

        CMS.debug("PKCS11Obj.parse: formatVersion read from blob: " + formatVersion);

        o.setFormatVersion(formatVersion);
        int objectVersion = b.getIntFrom2Bytes(2);

        CMS.debug("PKCS11Obj.parse: objectVersion read from blob: " + objectVersion);

        o.setObjectVersion(objectVersion);
        o.setCUID(b.substr(offset + 4, 10));

        int compressionType = b.getIntFrom2Bytes(14);
        int dataSize = b.getIntFrom2Bytes(16);

        int dataOffset = b.getIntFrom2Bytes(18);

        CMS.debug("PKCS11Obj.parse: commpressionType: " + compressionType + " DataSize:"
                + dataSize + "DataOffset: " + dataOffset + " data:  " + b.toHexString());

        TPSBuffer data = new TPSBuffer();

        if (compressionType == 0) { /* no compression */
            data.add(b.substr(offset + dataOffset, dataSize));
        } else if (compressionType == 1) { /* zlib */
            TPSBuffer compressedData = b.substr(offset + dataOffset, dataSize);

            TPSBuffer uncompressedData = uncompress(
                    compressedData);

            data = new TPSBuffer(uncompressedData);
        } else {
            throw new TPSException("PKCS11Obj.parse: error parsing object data!");
        }

        //CMS.debug("PKCS11Obj.parse: uncompressed data: " + data.toHexString());
        CMS.debug("PKCS11Obj.parse: uncompressed data");

        int objOffset = data.getIntFrom2Bytes(0);
        int objCount = data.getIntFrom2Bytes(2);

        //Check for absurd number of objects
        if (objCount < 0 || objCount > 100) {
            throw new TPSException("PKCS11Obj.parse: error parsing object data!");
        }

        TPSBuffer tokenName = data.substr(5, data.at(4));
        o.setTokenName(tokenName);

        if (tokenName != null)
            System.out.println("tokenName: " + tokenName.toHexString());
        System.out.println("uncompressed data size: " + data.size());

        CMS.debug("PKCS11Obj.parse" + "objcount = " + objCount);

        int curpos = objOffset;
        int nread = 0;
        for (int i = 0; i < objCount; i++) {
            CMS.debug("PKCS11Ob.parse: working on object " + i);
            ObjectSpec objSpec = ObjectSpec.parse(data, curpos);

            if (objSpec == null)
                continue;

            nread = objSpec.getParseReadSize();
            o.addObjectSpec(objSpec);

            char type = objSpec.getObjectType();
            int index = objSpec.getObjectIndex();

            CMS.debug("PKCS11Obj.parse " + "About to parse = " + type + ":" + index);
            System.out.println("PKCS11Obj.parse " + "About to parse = " + type + ":" + index);

            // add corresponding 'C' object for 'c'
            if (type == 'c') {
                for (int j = 0; j < objSpec.getAttributeSpecCount(); j++) {
                    AttributeSpec as = objSpec.getAttributeSpec(j);
                    if (as.getAttributeID() == PKCS11Constants.CKA_VALUE) {
                        if (as.getType() == (byte) 0) {
                            TPSBuffer cert = as.getValue();

                            long certid = ObjectSpec.createObjectID('C', index);
                            System.out.println("certid : " + certid);

                            ObjectSpec certSpec =
                                    ObjectSpec.parseFromTokenData(
                                            certid, cert);
                            o.addObjectSpec(certSpec);

                            objSpec.removeAttributeSpec(j);
                            break;
                        }
                    }
                }

            }

            curpos += nread;
        }
        return o;
    }

    public boolean doesCertIdExist(String certId) {

        boolean foundObj = false;
        for (ObjectSpec objSpec : objectSpecs) {

            String attrId = objSpec.getAttrId();

            if (attrId != null && attrId.equals(certId)) {
                foundObj = true;
                CMS.debug("PKCD11Obj.doesCertIdExist: match found new way!");
            }
        }

        return foundObj;
    }

    public void setFormatVersion(int v)
    {
        formatVersion = v;
    }

    public void setObjectVersion(int v)
    {
        CMS.debug("PKCS11Obj.setObjectVersion: setting to: " + v);
        objectVersion = v;
    }

    public int getFormatVersion()
    {
        return formatVersion;
    }

    public int getObjectVersion()
    {
        return objectVersion;
    }

    public void setCUID(TPSBuffer cuid)
    {
        this.cuid = cuid;
        ;
    }

    public TPSBuffer getCUID()
    {
        return cuid;
    }

    public void setTokenName(TPSBuffer tokenName)
    {
        this.tokenName = tokenName;
    }

    public TPSBuffer getTokenName()
    {
        return tokenName;
    }

    public int getObjectSpecCount()
    {
        return objectSpecs.size();
    }

    public ObjectSpec getObjectSpec(int p)
    {
        return objectSpecs.get(p);
    }

    public void addObjectSpec(ObjectSpec p)
    {
        CMS.debug("PKCS11Obj.adObjectSpec entering.. " + p);
        for (ObjectSpec objSpec : objectSpecs) {

            long oid = objSpec.getObjectID();

            if (oid == p.getObjectID()) {
                objectSpecs.remove(objSpec);

                String oidStr = objSpec.getAttrId();

                CMS.debug("PKCS11Obj.addObjectSpec: found dup, removing...: " + oidStr);
                break;
            }
        }

        objectSpecs.add(p);
    }

    public void removeObjectSpec(int p)
    {
        objectSpecs.remove(p);

    }

    public void removeAllObjectSpecs() {

        objectSpecs.clear();
    }

    private TPSBuffer getRawHeaderData(int compressionType, TPSBuffer data) {
        TPSBuffer header = new TPSBuffer();

        CMS.debug("PKCS11Obj.getRawHeaderData: " + " formatVersion: " + formatVersion + " objectVersion: "
                + objectVersion);
        header.add((byte) ((formatVersion >> 8) & 0xff));
        header.add((byte) (formatVersion & 0xff));
        header.add((byte) ((objectVersion >> 8) & 0xff));
        header.add((byte) (objectVersion & 0xff));
        header.add(cuid);
        // COMP_NONE = 0x00
        // COMP_ZLIB = 0x01

        header.add((byte) ((compressionType >> 8) & 0xff));
        header.add((byte) (compressionType & 0xff));
        int compressedDataSize = data.size();
        header.add((byte) ((compressedDataSize >> 8) & 0xff));
        header.add((byte) (compressedDataSize & 0xff));
        int compressedDataOffset = 20;
        header.add((byte) ((compressedDataOffset >> 8) & 0xff));
        header.add((byte) (compressedDataOffset & 0xff));

        CMS.debug("PKCS11Obj.getRawHeaderData: returning: " + header.toHexString());

        return header;

    }

    private TPSBuffer getRawData() {
        TPSBuffer data = new TPSBuffer();

        int objectOffset = tokenName.size() + 2 + 3;

        data.add((byte) ((objectOffset >> 8) & 0xff));
        data.add((byte) (objectOffset & 0xff));
        int objectCount = getObjectSpecCount();
        int objectCountX = objectCount;
        if (objectCountX == 0) {
            objectCountX = 0;
        } else {
            objectCountX = objectCountX - (objectCountX / 4);
        }

        data.add((byte) ((objectCountX >> 8) & 0xff));
        data.add((byte) (objectCountX & 0xff));
        data.add((byte) (tokenName.size() & 0xff));
        data.add(tokenName);

        CMS.debug("PKCS11Obj:getRawData: objectCount: " + objectCount);

        for (int i = 0; i < objectCount; i++) {
            ObjectSpec spec = getObjectSpec(i);

            char c = spec.getObjectType();
            long fixedAttrs = spec.getFixedAttributes();
            int xclass = (int) ((fixedAttrs & 0x70) >> 4);
            long cont_id = spec.getObjectIndex();
            long id = (int) (fixedAttrs & 0x0f);

            /* locate all certificate objects */
            if (c == 'c' && xclass == PKCS11Constants.CKO_CERTIFICATE) {

                //We need to use the container id, there may be more than one cert
                //with the same CKA_ID byte

                id = cont_id;

                /* locate the certificate object */
                for (int u = 0; u < objectCount; u++) {
                    ObjectSpec u_spec = getObjectSpec(u);
                    char u_c = u_spec.getObjectType();
                    long u_fixedAttrs =
                            u_spec.getFixedAttributes();
                    int u_xclass = (int) ((u_fixedAttrs & 0x70) >> 4);
                    int u_id = (int) (u_fixedAttrs & 0x0f);
                    if (u_c == 'C' && u_xclass == PKCS11Constants.CKO_CERTIFICATE && u_id == id) {
                        CMS.debug("PKCSObj:getRawData: found cert object: id: " + id + " u_id: " + u_id);

                        AttributeSpec u_attr =
                                u_spec.getAttributeSpec(0);
                        AttributeSpec n_attr = new AttributeSpec();
                        n_attr.setAttributeID(u_attr.getAttributeID());
                        n_attr.setType(u_attr.getType());
                        n_attr.setData(u_attr.getValue());
                        spec.addAttributeSpec(n_attr);
                    }
                }

                data.add(spec.getData());

                /* locate public object */
                for (int x = 0; x < objectCount; x++) {
                    ObjectSpec x_spec = getObjectSpec(x);
                    long x_fixedAttrs =
                            x_spec.getFixedAttributes();
                    int x_xclass = (int) ((x_fixedAttrs & 0x70) >> 4);
                    int x_id = (int) (x_fixedAttrs & 0x0f);
                    if (x_xclass == PKCS11Constants.CKO_PUBLIC_KEY && x_id == id) {
                        CMS.debug("PKCSObj:getRawData: found public key object: id: " + id);
                        data.add(x_spec.getData());
                    }
                }

                /* locate private object */
                for (int y = 0; y < objectCount; y++) {
                    ObjectSpec y_spec = getObjectSpec(y);
                    long y_fixedAttrs =
                            y_spec.getFixedAttributes();
                    int y_xclass = (int) ((y_fixedAttrs & 0x70) >> 4);
                    int y_id = (int) (y_fixedAttrs & 0x0f);
                    if (y_xclass == PKCS11Constants.CKO_PRIVATE_KEY && y_id == id) {
                        CMS.debug("PKCSObj:getRawData: found private key object: id: " + id);
                        data.add(y_spec.getData());
                    }
                }
            }
        }

        return data;

    }

    public TPSBuffer getData()
    {
        TPSBuffer data = getRawData();
        TPSBuffer header = getRawHeaderData(0, data);

        TPSBuffer result = new TPSBuffer(header);
        result.add(data);
        return result;
    }

    public TPSBuffer getCompressedData() throws TPSException, IOException
    {
        TPSBuffer data = getRawData(); // new TPSBuffer();

        CMS.debug("PKCS11Obj.getCompressedData: " + "before compress length = " + data.size());
        //CMS.debug("PKCS11Obj.getCompressedData: " + "before compress data = " + data.toHexString());

        System.out.println("Raw data before compress length: " + data.size());

        TPSBuffer src_buffer = new TPSBuffer(data);

        CMS.debug("PKCS11Obj.getCompressedData: " + "sizeof src_buffer = " + src_buffer.size());
        CMS.debug("PKCS11Obj.getCompressedData: " + "data size = " + data.size());

        TPSBuffer compressed = compress(src_buffer);
        TPSBuffer header = getRawHeaderData(0x01, compressed);

        TPSBuffer result = new TPSBuffer(header);
        result.add(compressed);

        //CMS.debug("PKCS11Obj.getCompressedData: PKCS11 Data: " + result.toHexString());
        CMS.debug("PKCS11Obj.getCompressedData: PKCS11 Data: ends");

        return result;
    }

    static private TPSBuffer compress(TPSBuffer uncompressedData) throws TPSException, IOException {

        if (uncompressedData == null) {
            throw new TPSException("PKCS11Obj.uncompress: bad input data!");
        }

        byte[] data = uncompressedData.toBytesArray();

        Deflater deflater = new Deflater();

        deflater.setInput(data);

        byte[] buffer = new byte[1024];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        deflater.finish();
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();
        CMS.debug("Original: " + data.length);
        CMS.debug("Compressed: " + output.length);

        TPSBuffer result = new TPSBuffer(output);

        return result;

    }

    static private TPSBuffer uncompress(TPSBuffer compressedData) throws TPSException, DataFormatException, IOException {

        if (compressedData == null) {
            throw new TPSException("PKCS11Obj.uncompress: bad input data!");
        }
        byte[] data = compressedData.toBytesArray();

        Inflater inflater = new Inflater();
        inflater.setInput(data);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();
        CMS.debug("Original: " + data.length);
        CMS.debug("Uncompressed: " + output.length);

        TPSBuffer result = new TPSBuffer(output);

        return result;
    }

    public static void main(String[] args) throws TPSException, DataFormatException, IOException {

        //Sample token data taken from previous server for
        // testing this functionality.

        String compressedTokenData =

                "%01%00%38%4c%53%4e%06%50%00%01" +
                        "%00%00%01%08%00%01%04%03%00%14" +
                        "%78%9c%63%e0%61%e0%64%cf%ca%4d" +
                        "%4c%cf%4b%55%48%36%64%00%81%89" +
                        "%0c%4c%40%92%99%81%41%ac%38%33" +
                        "%3d%2f%33%2f%5d%21%3b%b5%52%21" +
                        "%2d%bf%48%01%a2%0e%28%29%c8%c0" +
                        "%f8%c7%a0%89%f1%07%10%cf%59%c0" +
                        "%cc%c4%c8%c4%c4%e8%69%c0%c3%c6" +
                        "%a1%d5%e6%71%ce%96%85%99%89%95" +
                        "%c1%20%d2%50%c1%40%8e%8d%39%94" +
                        "%85%4b%58%3c%28%35%45%c1%23%b1" +
                        "%44%21%38%35%b9%b4%28%b3%a4%52" +
                        "%c1%25%3f%37%31%33%cf%50%d4%40" +
                        "%18%a4%82%5b%98%a7%20%3b%53%37" +
                        "%39%51%37%2b%31%39%db%c8%50%ce" +
                        "%40%06%24%cc%2c%2c%ea%9c%5a%54" +
                        "%92%99%96%99%9c%58%92%aa%e0%58" +
                        "%5a%92%91%0f%d2%6d%20%27%ce%6b" +
                        "%68%62%60%68%60%61%60%64%68%69" +
                        "%6a%10%05%e4%5a%02%b9%e6%50%ae" +
                        "%81%a1%a1%b8%81%28%c4%6a%be%90" +
                        "%fc%ec%d4%3c%05%6f%a0%07%42%8b" +
                        "%53%8b%0c%c5%0c%44%d8%b8%38%27" +
                        "%a9%75%4e%fe%a4%93%c2%c8%28%cc" +
                        "%06%f1%92%41%24%d0%25%ec%60%d7" +
                        "%33%31%42%bd%c1%cc%c8%ce%ec%c4" +
                        "%c0%12%dc%1d%9d%b7%91%ef%a6%dd" +
                        "%8a%27%01%3f%cf%3e%3d%7e%23%78" +
                        "%4e%8f%8c%c4%89%f7%ad%4b%1c%92" +
                        "%0c%2e%1d%5d%b5%46%ad%7a%aa%d9" +
                        "%7b%13%c7%6d%07%fb%0d%67%f5%45" +
                        "%ce%3e%52%b6%fc%ed%14%87%8a%04" +
                        "%29%3d%4e%b5%b5%2e%0f%33%fc%17" +
                        "%57%1b%54%1a%f0%01%5d%23%cb%cf" +
                        "%c8%f8%9f%05%18%38%6c%07%c0%fe" +
                        "%93%15%64%01%fa%bf%51%10%e2%02" +
                        "%87%a2%d4%94%8c%c4%12%bd%e4%fc" +
                        "%5c%03%59%90%2c%1f%8b%18%8b%88" +
                        "%d6%6f%81%1f%09%45%05%16%cf%64" +
                        "%27%1d%fe%e2%99%df%c7%64%c1%37" +
                        "%cf%40%1e%24%ad%cc%22%61%20%d6" +
                        "%20%72%ec%2a%6b%5d%94%e1%bb%c0" +
                        "%6f%05%33%5a%0e%ec%90%bb%b6%29" +
                        "%b1%d4%d1%80%13%a4%40%98%85%c9" +
                        "%80%01%35%4e%98%3d%18%0c%5c%99" +
                        "%14%19%16%d6%14%64%1c%9b%d2%a4" +
                        "%90%6e%1b%e3%56%cc%d6%36%7f%5a" +
                        "%8b%1a%87%f9%79%a7%a8%92%24%c7" +
                        "%49%4b%59%02%1e%32%29%78%9a%f0" +
                        "%70%45%1c%57%b9%77%60%b7%82%c6" +
                        "%fc%fc%09%8b%f7%a8%ec%6e%51%3d" +
                        "%60%cb%58%b3%e5%5d%af%c0%f9%a6" +
                        "%c7%d9%c6%c0%44%c0%c3%b0%10%94" +
                        "%4a%18%81%10%9c%5c%18%1b%18%18" +
                        "%b8%10%81%07%14%68%64%60%70%a4" +
                        "%38%00%b3%8d%80%c6%0b%33%6e%04" +
                        "%a5%4a%5c%76%25%1b%81%53%ee%24" +
                        "%58%ca%95%4c%cd%4b%2e%aa%2c%28" +
                        "%c9%cc%cf%c3%9a%78%7f%03%13%ee" +
                        "%77%a4%c4%eb%35%50%89%d7%10%35" +
                        "%f1%1a%52%39%f1%06%de%54%65%71" +
                        "%10%e3%2a%fe%5e%aa%7a%9e%77%f3" +
                        "%fe%e6%0d%ed%02%0d%37%0e%33%71" +
                        "%2c%58%65%c4%2f%b9%53%6c%5d%f7" +
                        "%c4%53%07%d7%eb%5d%79%df%d8%fc" +
                        "%43%c3%c0%6b%f3%89%ef%47%96%3e" +
                        "%72%7e%9b%fc%f6%4c%83%77%bf%ce" +
                        "%5d%7b%35%cc%c4%cb%aa%40%74%e2" +
                        "%fd%7d%75%09%57%fb%01%4f%cd%ab" +
                        "%4b%b3%58%5b%f7%9f%bf%a7%be%4a" +
                        "%2c%85%82%c4%eb%ce%60%e0%c2%a4" +
                        "%10%1f%7c%75%eb%26%9f%83%2d%8f" +
                        "%f5%3a%76%b5%f2%d4%cf%3b%de%b7" +
                        "%bb%e9%56%8a%ef%f4%af%3c%31%3c" +
                        "%76%77%b9%1a%98%14%32%3e%09%cd" +
                        "%fc%c8%f9%f3%c9%b2%45%21%f3%b6" +
                        "%2c%56%0c%39%fb%2d%e5%7f%da%de" +
                        "%fd%ce%33%17%d4%c8%af%15%c8%dd" +
                        "%99%6d%0a%4a%2a%01%8b%88%49%bb" +
                        "%94%86%5f%b6%09%d0%78%81%85%9b" +
                        "%f0%a6%5d%63%70%da%9d%0c%4b%bb" +
                        "%32%38%d3%ae%02%58%29%96%b2%d7" +
                        "%84%be%c9%d7%d8%d0%c8%c8%00%98" +
                        "%50%4d%8c%c1%65%af%85%a1%11%28" +
                        "%09%83%b9%d4%4d%be%49%31%e1%27" +
                        "%cf%4e%93%9b%7a%35%6d%1b%db%e1" +
                        "%10%3b%ee%c5%1e%b6%1f%23%ee%7c" +
                        "%9c%b7%6e%ee%aa%57%a2%7f%95%fb" +
                        "%fd%3a%3b%ab%de%46%cb%ff%62%9e" +
                        "%ac%90%66%b3%f0%58%b3%dd%ed%38" +
                        "%e1%16%9f%a4%56%8d%fb%6b%db%96" +
                        "%ba%ef%aa%a4%28%f9%66%b5%2f%9d" +
                        "%36%cd%7b%52%6b%4b%68%e5%8d%57" +
                        "%92%92%5f%78%36%7e%31%a4%b4%ec" +
                        "%55%a8%95%da%7c%76%42%8a%19%a3" +
                        "%d9%f1%03%27%af%cb%14%fb%3b%44" +
                        "%cf%dc%b1%fc%a1%dc%8f%95%31%b9" +
                        "%5f%ff%2e%aa%b8%00%2c%9d%f7%b9" +
                        "%1e%bd%c5%2e%78%b4%48%4e%aa%7b" +
                        "%92%e1%16%5d%af%cd%1f%94%93%96" +
                        "%3b%27%c5%ed%ab%f6%0c%dd%cb%73" +
                        "%fd%7a%b6%39%38%fd%2e%26%26%fd" +
                        "%52%1a%80%d9%66%e0%f4%bb%19%5f" +
                        "%fa%05%00%21%15%7f%b0";

        System.out.println("Test PKCS11 Blob data: " + compressedTokenData);
        System.out.println("Test Data: Len: " + compressedTokenData.length());

        // Test getting integer values from a TPSBuffer

        byte[] value = { (byte) 99, (byte) 49, (byte) 0, (byte) 0 };

        TPSBuffer valBuf = new TPSBuffer(value);

        long l1 = valBuf.getLongFrom4Bytes(0);

        int i1 = valBuf.getIntFrom2Bytes(0);

        int i2 = valBuf.getIntFrom1Byte(0);

        System.out.println("4 bytes long: " + l1 + " 2 bytes int: " + i1 + " 1 byte int: " + i2);

        // Now test the parsing and un-parsing of the data, the result at the end should be
        // the same as the original data.
        // The data above is an exact copy of a blob taken off of a real token in the
        //  old TPS.

        byte[] decoded = Util.uriDecodeFromHex(compressedTokenData);

        System.out.println("decoded compressed datat size: " + decoded.length);

        // This is buffer containing sample copressed pkcs#11 blob.
        TPSBuffer tokenData = new TPSBuffer(decoded);

        // Parse the given token data into PKCS#11 objects and attributes

        PKCS11Obj object = PKCS11Obj.parse(tokenData, 0);

        String certId = "C1";
        boolean exists = object.doesCertIdExist(certId);

        System.out.println("CertID " + certId + " exists: " + exists);

        int nextFreeCertId = object.getNextFreeCertIdNumber();

        System.out.println("Next Free CertID: " + nextFreeCertId);

        // This gets the compressed blob that will go out to token of the parsed data.
        TPSBuffer implodedData = object.getCompressedData();

        System.out.println("imploded token data size: " + implodedData.size());

        String encodedImplodedData = implodedData.toHexString();

        System.out.println("encodedImplodedData: " + encodedImplodedData);

        // Now test to see if both blobs are identical

        boolean identical = implodedData.equals(tokenData);

        System.out.println("Before and after comparison result: Are the blobs identical?: " + identical);

    }

    public int getOldFormatVersion() {
        return oldFormatVersion;
    }

    public void setOldFormatVersion(int oldFormatVersion) {
        this.oldFormatVersion = oldFormatVersion;
    }

    public int getOldObjectVersion() {
        return oldObjectVersion;
    }

    public void setOldObjectVersion(int oldObjectVersion) {
        this.oldObjectVersion = oldObjectVersion;
    }

    public int getNextFreeCertIdNumber() {

        int free_cert_id = 0;

        int[] certTable = new int[100];

        int numObjs = getObjectSpecCount();

        for (int i = 0; i < numObjs; i++) {
            ObjectSpec os = getObjectSpec(i);
            if (os == null)
                continue;

            char type = os.getObjectType();
            int index = os.getObjectIndex();

            if (type == 'C') { //found a certificate
                if (index >= 0 && index < 100) {
                    certTable[index] = 1;
                }
            }
        }

        for (int i = 0; i < 100; i++) {
            if (certTable[i] == 0) {

                free_cert_id = i;
                break;
            }
        }

        CMS.debug("TPSEnrollProcessor.getNextFreeCertIdNumber: returning free cert id: " + free_cert_id );

        return free_cert_id;
    }

}
