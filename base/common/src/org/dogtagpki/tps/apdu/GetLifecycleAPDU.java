package org.dogtagpki.tps.apdu;

import org.dogtagpki.tps.main.TPSBuffer;


public class GetLifecycleAPDU extends APDU {
    public GetLifecycleAPDU() {
        setCLA((byte) 0xB0);
        setINS((byte) 0xf2);
        setP1((byte) 0x0);
        setP2((byte) 0x0);
    }

    @Override
    public Type getType()
    {
        return Type.APDU_GET_LIFECYCLE;
    }

    @Override
    public TPSBuffer getEncoding()
    {
        TPSBuffer encoding = new TPSBuffer();

        encoding.add(cla);
        encoding.add(ins);
        encoding.add(p1);
        encoding.add(p2);
        encoding.add((byte) 0x01);

        return encoding;
    } /* Encode */


}
