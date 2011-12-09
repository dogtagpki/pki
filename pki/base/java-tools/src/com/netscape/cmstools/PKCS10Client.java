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
package com.netscape.cmstools;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyPair;
import java.security.MessageDigest;

import netscape.security.x509.X500Name;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkcs10.CertificationRequestInfo;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.util.HMACDigest;


/**
 * Generates a 1024-bit RSA key pair in the security database, constructs a
 * PKCS#10 certificate request with the public key, and outputs the request
 * to a file.
 * <p>
 * PKCS #10 is a certification request syntax standard defined by RSA. A CA
 * may support multiple types of certificate requests. The Certificate System
 * CA supports KEYGEN, PKCS#10, CRMF, and CMC.
 * <p>
 * To get a certificate from the CA, the certificate request needs to be
 * submitted to and approved by a CA agent. Once approved, a certificate is
 * created for the request, and certificate attributes, such as extensions,
 * are populated according to certificate profiles. 
 * <p>
 * @version $Revision$, $Date$
 */
public class PKCS10Client
{
        
    private static void printUsage() {
        System.out.println("Usage: PKCS10Client -p <certdb password> -d <location of certdb> -o <output file which saves the base64 PKCS10> -s <subjectDN>\n");
    }

    public static void main(String args[]) 
    {
        String dbdir = null, ofilename = null, password = null, subjectName = null;

        if (args.length != 8) {
            printUsage();
            System.exit(1);
        }

        for (int i=0; i<args.length; i++) { 
            String name = args[i];
            if (name.equals("-p")) {
                password = args[i+1];
            } else if (name.equals("-d")) {
                dbdir = args[i+1];
            } else if (name.equals("-o")) {
                ofilename = args[i+1];
            } else if (name.equals("-s")) {
                subjectName = args[i+1];
            }
        }
 
        if (password == null || ofilename == null || subjectName == null) {
            System.out.println("Illegal input parameters.");
            printUsage();
            System.exit(1);
        }
    
        if (dbdir == null)
            dbdir = ".";

	try { 
            String mPrefix = "";
            CryptoManager.InitializationValues vals =
              new CryptoManager.InitializationValues(dbdir, mPrefix,
              mPrefix, "secmod.db");

            CryptoManager.initialize(vals);
            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();
            Password pass = new Password(password.toCharArray());

            token.login(pass);
            KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA); 
            kg.initialize(1024);
            KeyPair pair = kg.genKeyPair(); 

            // Add idPOPLinkWitness control
            String secretValue = "testing";
            byte[] key1 = null;
            byte[] finalDigest = null;
            MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");
            key1 = SHA1Digest.digest(secretValue.getBytes());

/* seed */
byte[] b = 
{0x10, 0x53, 0x42, 0x24, 0x1a, 0x2a, 0x35, 0x3c,
 0x7a, 0x52, 0x54, 0x56, 0x71, 0x65, 0x66, 0x4c,
 0x51, 0x34, 0x35, 0x23, 0x3c, 0x42, 0x43, 0x45,
 0x61, 0x4f, 0x6e, 0x43, 0x1e, 0x2a, 0x2b, 0x31,
 0x32, 0x34, 0x35, 0x36, 0x55, 0x51, 0x48, 0x14,
 0x16, 0x29, 0x41, 0x42, 0x43, 0x7b, 0x63, 0x44,
 0x6a, 0x12, 0x6b, 0x3c, 0x4c, 0x3f, 0x00, 0x14,
 0x51, 0x61, 0x15, 0x22, 0x23, 0x5f, 0x5e, 0x69};

            HMACDigest hmacDigest = new HMACDigest(SHA1Digest, key1);
            hmacDigest.update(b);
            finalDigest = hmacDigest.digest();

            OCTET_STRING ostr = new OCTET_STRING(finalDigest);
            Attribute attr = new Attribute(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness, ostr);
    
            SET attributes = new SET();
            attributes.addElement(attr);
            Name n = getJssName(subjectName);
            SubjectPublicKeyInfo subjectPub = new SubjectPublicKeyInfo(pair.getPublic()); 
            CertificationRequestInfo certReqInfo = 
              new CertificationRequestInfo(new INTEGER(0), n, subjectPub, attributes);
            CertificationRequest certRequest = new CertificationRequest(certReqInfo,
              pair.getPrivate(), SignatureAlgorithm.RSASignatureWithMD5Digest);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            certRequest.encode(bos);
            byte[] bb = bos.toByteArray();

            String b64E = com.netscape.osutil.OSUtil.BtoA(bb);
 
            System.out.println("");
            System.out.println(b64E);
            System.out.println("");
    
            PrintStream ps = null;
            ps = new PrintStream(new FileOutputStream(ofilename));
            ps.println(b64E);
            ps.flush();
            ps.close();
        } catch (Exception e) {
        }
    }

    static Name getJssName(String dn) 
    {

        X500Name x5Name = null;

        try {
            x5Name= new X500Name(dn);
        } catch(IOException e) {

            System.out.println("Illegal Subject Name:  " + dn + " Error: "  + e.toString());
            System.out.println("Filling in default Subject Name......");
            return null;
        }

        Name ret = new Name();
        netscape.security.x509.RDN[] names = null;
        names =  x5Name.getNames();
        int nameLen = x5Name.getNamesLength();

        netscape.security.x509.RDN cur = null;

        for(int i = 0; i < nameLen ; i++)
        {
            cur = names[i];
            String rdnStr = cur.toString();
            String[] split = rdnStr.split("=");

            if(split.length != 2)
                continue;

            try {
                if(split[0].equals("UID"))
                {
                    ret.addElement(new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"),  new PrintableString(split[1]))); 
 //                 System.out.println("UID found : " + split[1]);
                }

                if(split[0].equals("C"))
                {
                    ret.addCountryName(split[1]);
  //                   System.out.println("C found : " + split[1]);
                    continue;
                }

                if(split[0].equals("CN"))
                {
                    ret.addCommonName(split[1]);
   //                  System.out.println("CN found : " + split[1]);
                    continue;
                }

                if(split[0].equals("L"))
                {
                    ret.addLocalityName(split[1]);
    //                 System.out.println("L found : " + split[1]);
                    continue;
                }

                if(split[0].equals("O"))
                {
                    ret.addOrganizationName(split[1]);
     //                System.out.println("O found : " + split[1]);
                    continue;
                }

                if(split[0].equals("ST"))
                {
                    ret.addStateOrProvinceName(split[1]);
      //               System.out.println("ST found : " + split[1]);
                    continue;
                }

                if(split[0].equals("OU"))
                {
                    ret.addOrganizationalUnitName(split[1]);
       //              System.out.println("OU found : " + split[1]);
                    continue;
                }
            }  catch (Exception e)  {
                System.out.println("Error constructing RDN: " + rdnStr + " Error: "  + e.toString());
                continue;
            }
        }

        return ret;
    }
}
