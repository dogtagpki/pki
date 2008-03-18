// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package netscape.security.x509;

import java.io.*;
import java.util.StringTokenizer;
import java.lang.Integer;

import netscape.security.util.*;

/**
 * This class implements the OtherName as required by the GeneralNames
 * ASN.1 object.
 *
 *  OtherName ::= SEQUENCE {
 *     type-id OBJECT IDENTIFIER,
 *     value [0] EXPLICIT ANY DEFINED BY type-id
 *  }
 *
 * @see GeneralName
 * @see GeneralNameInterface
 * @see GeneralNames
 *
 * @version 1.2
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class OtherName implements GeneralNameInterface {
    private ObjectIdentifier mOID = null;
    private byte[] mData = null;

    /**
     * Create the IPAddressName object from the passed encoded Der value.
     *
     * @param derValue the encoded DER IPAddressName.
     * @exception IOException on error.
     */
    public OtherName(DerValue derValue) throws IOException {
        decodeThis(derValue);
    }

    public OtherName(ObjectIdentifier oid, byte data[]) {
      mOID = oid;
      DerOutputStream dos = new DerOutputStream();
      try {
          dos.putDerValue(new DerValue(data));
      } catch (IOException e) {
      }
      mData = dos.toByteArray();
    }

    /**
     * Constructs a string-based other name.
     */
    public OtherName(ObjectIdentifier oid, byte tag, String value) {
      mOID = oid;
      DerOutputStream dos = new DerOutputStream();
      try {
        if (tag == DerValue.tag_PrintableString) {
          dos.putPrintableString(value);
        } else if (tag == DerValue.tag_IA5String) {
          dos.putIA5String(value);
        } else if (tag == DerValue.tag_BMPString) {
          dos.putBMPString(value);
        } else if (tag == DerValue.tag_UTF8String) {
          dos.putUTF8String(value);
        }
      } catch (IOException e) {
      }
      mData = dos.toByteArray();
    }

    public OtherName(ObjectIdentifier oid, String value) {
      mOID = oid;
      DerOutputStream dos = new DerOutputStream();
      try {
        dos.putPrintableString(value);
      } catch (IOException e) {
      }
      mData = dos.toByteArray();
    }

    /**
     * Create the IPAddressName object with the specified name.
     *
     * @param name the IPAddressName.
     */
    public OtherName(byte[] data) {
        try {
          decodeThis(new DerValue(data));
        } catch (IOException e) {
        }
    }

    public ObjectIdentifier getOID()
    {
      return mOID;
    }

    /**
     * Return the type of the GeneralName.
     */
    public int getType() {
        return (GeneralNameInterface.NAME_ANY);
    }

    /**
     * Encode the IPAddress name into the DerOutputStream.
     *
     * @param out the DER stream to encode the IPAddressName to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        //encoding the attributes
        tmp.putOID(mOID);
        DerOutputStream tmp1 = new DerOutputStream();
        tmp1.write(mData);
        tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true,
          (byte)0x80), tmp1);

        out.write(DerValue.tag_SequenceOf, tmp);
    }

    public void decode(InputStream in) throws IOException {
        DerValue val = new DerValue(in);
        decodeThis(val);
    }

    // Decode this extension value
    private void decodeThis(DerValue derVal) throws IOException {

    //    if (derVal.tag != DerValue.tag_Sequence) {
     //       throw new IOException("Invalid encoding for other name");
      //  }


        // Decode all the Attributes
        mOID = derVal.data.getOID();
        // skip tag 
        DerValue tag = derVal.data.getDerValue();
        // read data 
        DerValue data = tag.data.getDerValue();
        mData = data.toByteArray();
    }

    public byte[] getValue() {
        return mData;
    }

    /**
     * Return a printable string of IPaddress
     */
    public String toString() {
        if (mData != null) {
            try {
            DerValue data = new DerValue(mData);
            if (data.tag == DerValue.tag_PrintableString) {
              return "OtherName: (PrintableString)" + mOID + "," + data.getPrintableString();
            } else if (data.tag == DerValue.tag_IA5String) {
              return "OtherName: (IA5String)" + mOID + "," + data.getIA5String();
            } else if (data.tag == DerValue.tag_BMPString) {
              return "OtherName: (BMPString)" + mOID + "," + data.getIA5String();
            } else if (data.tag == DerValue.tag_UTF8String) {
              return "OtherName: (UTF8String)" + mOID + "," + data.getUTF8String();
            } else {
              return "OtherName: (Any)" + mOID + "," + toStr(data.toByteArray());
            }
            }  catch (IOException e) {
         
              return "OtherName: (Any)" + mOID + "," + toStr(mData);
            }
        } else {
            return "OtherName: ";
        }
    }

    public String toStr(byte data[]) {
        StringBuffer b = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
           if ((data[i] & 0xff) < 16) {
              b.append("0");
           }
           b.append(Integer.toString((int)(data[i] & 0xff), 0x10)); 
        }
        return b.toString();
    }
}


