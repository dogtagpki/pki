package com.netscape.certsrv.dbs.keydb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyIdTest {

    // data #1: zero
    String DATA1_HEX = "0x00";
    String DATA1_JSON = "\"0x00\"";
    byte[] DATA1_BYTES = new byte[] {
            (byte) 0x00
    };

    // data #2: long zero
    String DATA2_HEX = "0x00000000";
    String DATA2_JSON = "\"0x00000000\"";
    byte[] DATA2_BYTES = new byte[] {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    // data #3: 1-byte number
    String DATA3_HEX = "0x06";
    String DATA3_JSON = "\"0x06\"";
    byte[] DATA3_BYTES = new byte[] {
            (byte) 0x06
    };

    // data #4: 16-byte number
    String DATA4_HEX = "0xa8405e456904f79ccb9118196023153b";
    String DATA4_JSON = "\"0xa8405e456904f79ccb9118196023153b\"";
    byte[] DATA4_BYTES = new byte[] {
            (byte) 0xa8, (byte) 0x40, (byte) 0x5e, (byte) 0x45,
            (byte) 0x69, (byte) 0x04, (byte) 0xf7, (byte) 0x9c,
            (byte) 0xcb, (byte) 0x91, (byte) 0x18, (byte) 0x19,
            (byte) 0x60, (byte) 0x23, (byte) 0x15, (byte) 0x3b
    };

    // data #5: 20-byte number with leading zero
    String DATA5_HEX = "0x004128630eae9cdaf342b21e55571019c4f06368";
    String DATA5_JSON = "\"0x004128630eae9cdaf342b21e55571019c4f06368\"";
    byte[] DATA5_BYTES = new byte[] {
            (byte) 0x00, (byte) 0x41, (byte) 0x28, (byte) 0x63,
            (byte) 0x0e, (byte) 0xae, (byte) 0x9c, (byte) 0xda,
            (byte) 0xf3, (byte) 0x42, (byte) 0xb2, (byte) 0x1e,
            (byte) 0x55, (byte) 0x57, (byte) 0x10, (byte) 0x19,
            (byte) 0xc4, (byte) 0xf0, (byte) 0x63, (byte) 0x68
    };

    Object[][] TEST_DATA = {
            new Object[] { DATA1_HEX, DATA1_JSON, DATA1_BYTES },
            new Object[] { DATA2_HEX, DATA2_JSON, DATA2_BYTES },
            new Object[] { DATA3_HEX, DATA3_JSON, DATA3_BYTES },
            new Object[] { DATA4_HEX, DATA4_JSON, DATA4_BYTES },
            new Object[] { DATA5_HEX, DATA5_JSON, DATA5_BYTES }
    };

    @Test
    public void run() throws Exception {

        for (int i = 0; i < TEST_DATA.length; i++) {
            System.out.println("Testing data #" + (i + 1));

            // convert hex string into KeyId
            String hex = (String) TEST_DATA[i][0];
            KeyId keyID = new KeyId(hex);

            // convert KeyId into hex string
            assertEquals(hex, keyID.toHexString());

            // convert KeyId into JSON
            String json = (String) TEST_DATA[i][1];
            assertEquals(json, keyID.toJSON());

            // convert JSON into KeyId
            KeyId afterJSON = JSONSerializer.fromJSON(json, KeyId.class);
            assertEquals(keyID, afterJSON);

            // convert KeyId into bytes
            byte[] bytes = (byte[]) TEST_DATA[i][2];
            assertArrayEquals(bytes, keyID.toByteArray());

            // convert bytes into KeyId
            KeyId afterBytes = new KeyId(bytes);
            assertEquals(keyID, afterBytes);
        }
    }
}
