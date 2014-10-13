package org.dogtagpki.tps.apdu;

import org.dogtagpki.tps.main.TPSBuffer;

import com.netscape.certsrv.apps.CMS;

public class InstallLoadGP211APDU extends APDU {

    public InstallLoadGP211APDU(TPSBuffer packageAID, TPSBuffer sdAID,
            int fileLen) {
        setCLA((byte) 0x84);
        setINS((byte) 0xE6);
        setP1((byte) 0x02);
        setP2((byte) 0x00);


        CMS.debug("InstlalLoadGP211APDU: packageAID " + packageAID.toHexString() + " aid size: " + packageAID.size() + " fileLen: " + fileLen);

        TPSBuffer inputData = new TPSBuffer();

      //  inputData.add((byte) 0x0);

        inputData.add((byte) packageAID.size());
        inputData.add(packageAID);
        inputData.add((byte) sdAID.size());
        inputData.add(sdAID);

        //work in file size here

        inputData.add((byte) 0x00);
        inputData.add((byte) 0x06);

        inputData.add((byte) 0xEF);
        inputData.add((byte) 0x04);
        inputData.add((byte) 0xc6);


        inputData.add((byte) 0x02);
        int finalLen = fileLen + 24 + sdAID.size();
        inputData.addInt2Bytes(finalLen);

        //assume no load file data block hash
        inputData.add((byte) 0x0);

        setData(inputData);

        trailer = new TPSBuffer();
        trailer.add((byte)0x0);
    }

}
