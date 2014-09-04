package org.dogtagpki.server.tps.main;

import org.dogtagpki.tps.main.TPSBuffer;

public class AttributeSpec {

    public AttributeSpec() {
    }

    private long id;
    private byte type;
    private TPSBuffer data;

    public void setAttributeID(long attribute_id) {
        id = attribute_id;
    }

    public long getAttributeID() {
        return id;
    }

    public void setType(byte type) {
        this.type = type;
    }

    public byte getType() {
        return type;
    }

    public void setData(TPSBuffer data) {
        this.data = data;

    }

    public TPSBuffer getData() {
        TPSBuffer theData = new TPSBuffer();
        theData.addLong4Bytes(id);
        theData.add(type);

        if (type == 0) { /* String */
            theData.addInt2Bytes(data.size());
        }
        theData.add(data);
        return theData;
    }

    public TPSBuffer getValue() {
        return data;
    }

    public static AttributeSpec parse(TPSBuffer b, int offset) {
        AttributeSpec o = new AttributeSpec();

        long id = b.getLongFrom4Bytes(offset);

        o.setAttributeID(id);

        o.setType(b.at(offset + 4));
        // DatatypeString contains two bytes for AttributeLen of AttributeData
        TPSBuffer theData;
        if (o.getType() == (byte) 0)
            theData = b.substr(offset + 5 + 2, b.size() - 5 - 2);
        else
            theData = b.substr(offset + 5, b.size() - 5);

        o.setData(theData);
        return o;

    }

}
