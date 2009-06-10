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
//
//  "70ToTxt/src/Main.java" is based upon a copy "62ToTxt/src/Main.java".
//
//  Always comment any new code sections with a "CMS 7.0" header, and
//  apply these changes forward to all other "*ToTxt/src/Main.java" files
//  (including this comment header) so that these differences will only
//  appear when this file is diffed against an earlier "*ToTxt" version.
//
//  This file should always be maintained by executing the following command:
//
//      diff 62ToTxt/src/Main.java 70ToTxt/src/Main.java
//

import java.io.*;
import java.math.*;
import java.util.*;
import sun.misc.*;
import org.mozilla.jss.*;               // CMS 4.5 and later
import org.mozilla.jss.crypto.*;        // CMS 4.5 and later
import netscape.security.util.*;

public class Main
{
	public static void main(String args[]) 
	{
		try {
			// initialize CryptoManager in CMS 4.5 and later
			CryptoManager.initialize(".");
			// load JSS provider in CMS 4.5 and later
			java.security.Security.removeProvider("SUN version 1.2");
			// The following call to "java.security.Security.insertProviderAt()"
			// is no longer commented out in CMS 4.5 and later
			java.security.Security.insertProviderAt(
				new netscape.security.provider.CMS(), 0); 
			java.security.Provider ps[] = 
				java.security.Security.getProviders();
			if (ps == null || ps.length <= 0) { 
				System.err.println("Java Security Provider NONE"); 
			} else { 
				for (int x = 0; x < ps.length; x++) { 
					System.err.println("Java Security Provider " + x + " class=" + ps[x]); 
				} 
			}

			// Parse the File
			CMS70LdifParser parser = null;
			if (args.length == 1) {
			  parser = new CMS70LdifParser(args[0]);
			} else if (args.length == 2) {
			  parser = new CMS70LdifParser(args[0], args[1]);
			} else {
			  throw new IOException("Invalid Parameters");
			}
			parser.parse();
		} catch (Exception e) {
			System.err.println("ERROR: " + e.toString());
			e.printStackTrace();
		}
	}
}

class CMS70LdifParser
{
	// constants
	private static final String DN = 
		"dn:";
	// Directory Servers in CMS 4.7 and later use "requestAttributes"
	private static final String REQUEST_ATTRIBUTES = 
		"requestAttributes::";
	private static final String BEGIN = 
		"--- BEGIN ATTRIBUTES ---";
	private static final String END = 
		"--- END ATTRIBUTES ---";

	// variables
	private String mFilename = null;
	private String mErrorFilename = null;
	private PrintWriter mErrorPrintWriter = null;

	public CMS70LdifParser(String filename)
	{
		mFilename = filename;
	}

	public CMS70LdifParser(String filename, String errorFilename)
	{
		mFilename = filename;
		mErrorFilename = errorFilename;
	}

	public void parse() throws Exception
	{ 
		if (mErrorFilename != null) {
		    mErrorPrintWriter = new PrintWriter(new FileOutputStream(mErrorFilename));
		}
		BufferedReader reader = new BufferedReader(
			new FileReader(mFilename)); 
		String line = null; 
		String dn = null; 
		StringBuffer requestAttributes = null;
		while ((line = reader.readLine()) != null) { 
			if (line.startsWith(DN)) {
				dn = line;
			}
			if (line.startsWith(REQUEST_ATTRIBUTES)) {
				requestAttributes = new StringBuffer();
				// System.out.println(line);
				requestAttributes.append(
					line.substring(REQUEST_ATTRIBUTES.length(), 
					line.length()).trim());
				continue;
			}
			if (requestAttributes == null) {
				System.out.println(line);
				continue;
			}
			if (line.startsWith(" ")) {
				// System.out.println(line);
				requestAttributes.append(line.trim());
			} else {
				parseAttributes(dn, requestAttributes);
				requestAttributes = null;
				System.out.println(line);
			}
		} 
	}

	public void parseAttributes(String dn, StringBuffer attrs) throws Exception
	{
		BASE64Decoder decoder = new BASE64Decoder();
		decodeHashtable(dn, decoder.decodeBuffer(attrs.toString()));
		
//		System.out.println(attrs);
	}

	public Object decode(byte[] data) throws 
		ObjectStreamException, 
		IOException, 
		ClassNotFoundException 
	{ 
		ByteArrayInputStream bis = new ByteArrayInputStream(data); 
		ObjectInputStream is = new ObjectInputStream(bis); 
		return is.readObject(); 
	}

	public void decodeHashtable(String dn, byte[] data) throws Exception
	{
		ByteArrayInputStream bis = new ByteArrayInputStream(data); 
		ObjectInputStream is = new ObjectInputStream(bis); 

		System.out.println(BEGIN);
		String key = null; 
		while (true) 
		{ 
			key = (String)is.readObject(); 
			// end of table is marked with null 
			if (key == null) break; 
			try {
			  byte[] bytes = (byte[])is.readObject(); 
			  Object obj = decode(bytes);
			  output(key, obj);
			} catch (Exception e) {
			  if (mErrorPrintWriter != null) {
			      if (dn != null) {
			          mErrorPrintWriter.println(dn);
			      }
			      mErrorPrintWriter.println("Skipped " + key);
			  }
			}
		} 
		System.out.println(END);
	}

	public void output(String key, Object obj) throws Exception
	{
		if (obj instanceof String) {
			System.out.println(" " +
				key + ":" + obj.getClass().getName() + "=" + 
				obj);
		} else if (obj instanceof netscape.security.x509.CertificateX509Key) {
			netscape.security.x509.CertificateX509Key o =
				(netscape.security.x509.CertificateX509Key)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" + 
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof netscape.security.x509.CertificateSubjectName) {
			netscape.security.x509.CertificateSubjectName o =
				(netscape.security.x509.CertificateSubjectName)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" +
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof netscape.security.x509.CertificateExtensions) {
			netscape.security.x509.CertificateExtensions o =
				(netscape.security.x509.CertificateExtensions)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" +
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof netscape.security.x509.X509CertInfo) {
			netscape.security.x509.X509CertInfo o =
				(netscape.security.x509.X509CertInfo)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" +
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof netscape.security.x509.X509CertImpl) {
			netscape.security.x509.X509CertImpl o =
				(netscape.security.x509.X509CertImpl)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" + 
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof netscape.security.x509.CertificateChain) {
			netscape.security.x509.CertificateChain o =
				(netscape.security.x509.CertificateChain)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" + 
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof netscape.security.x509.X509CertImpl[]) {
			netscape.security.x509.X509CertImpl o[] =
				(netscape.security.x509.X509CertImpl[])obj;
			for (int i = 0; i < o.length; i++) {
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o[i].encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o[i].getClass().getName() +"["+o.length+","+i+"]" + "=" + 
				encoder.encode(bos.toByteArray()));
			}
		} else if (obj instanceof netscape.security.x509.X509CertInfo[]) {
			netscape.security.x509.X509CertInfo o[] =
				(netscape.security.x509.X509CertInfo[])obj;
			for (int i = 0; i < o.length; i++) {
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o[i].encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o[i].getClass().getName() + "["+o.length + "," + i+"]"+"=" + 
				encoder.encodeBuffer(bos.toByteArray()));
			}
		} else if (obj instanceof netscape.security.x509.RevokedCertImpl[]) {
			netscape.security.x509.RevokedCertImpl o[] =
				(netscape.security.x509.RevokedCertImpl[])obj;
			for (int i = 0; i < o.length; i++) {
				DerOutputStream bos = 
					new DerOutputStream();
				o[i].encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o[i].getClass().getName() +"["+o.length+","+i+"]" + "=" + 
				encoder.encode(bos.toByteArray()));
			}
		} else if (obj instanceof java.security.cert.Certificate[]) {
			java.security.cert.Certificate o[] =
				(java.security.cert.Certificate[])obj;
			for (int i = 0; i < o.length; i++) {
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o[i].getClass().getName() +"["+o.length+","+i+"]" + "=" + 
				encoder.encode(o[i].getEncoded()));
			}
		} else if (obj instanceof com.netscape.cmscore.base.ArgBlock) {
			// CMS 6.1:  created new "com.netscape.certsrv.base.IArgBlock" and
			//           moved old "com.netscape.certsrv.base.ArgBlock"
			//           to "com.netscape.cmscore.base.ArgBlock"
			com.netscape.cmscore.base.ArgBlock o =
			(com.netscape.cmscore.base.ArgBlock)obj;
			Enumeration e = o.elements();
			while (e.hasMoreElements()) {
				String k = (String)e.nextElement();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" +
				k + "=" +(String)o.get(k));
			}
		} else if (obj instanceof com.netscape.cmscore.dbs.KeyRecord) {
			// CMS 6.0:  moved "com.netscape.certsrv.dbs.keydb.KeyRecord"
			//           to "com.netscape.cmscore.dbs.KeyRecord"
			com.netscape.cmscore.dbs.KeyRecord o =
			(com.netscape.cmscore.dbs.KeyRecord)obj;
			Enumeration e = o.getElements();
			while (e.hasMoreElements()) {
				String k = (String)e.nextElement();
				Object ob = o.get(k);
				if (ob != null) {
				if (ob instanceof java.util.Date) {
					System.out.println(" " +
					key + ":" + o.getClass().getName() + "=" +
					k + ":" + ob.getClass().getName() + "=" + ((java.util.Date)ob).getTime());
				} else if (ob instanceof byte[]) {
					BASE64Encoder encoder = new BASE64Encoder();
					System.out.println(" " +
					key + ":" + o.getClass().getName() + "=" +
					k + ":" + ob.getClass().getName() + "=" + encoder.encode((byte[])ob));

				} else {
					System.out.println(" " +
					key + ":" + o.getClass().getName() + "=" +
					k + ":" + ob.getClass().getName() + "=" + ob);
				}
				}
			}
		} else if (obj instanceof com.netscape.cmscore.kra.ProofOfArchival) {
			// CMS 6.0:  moved "com.netscape.certsrv.kra.ProofOfArchival"
			//           to "com.netscape.cmscore.kra.ProofOfArchival"
			com.netscape.cmscore.kra.ProofOfArchival o =
				(com.netscape.cmscore.kra.ProofOfArchival)obj;
				DerOutputStream bos = 
					new DerOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" + 
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof com.netscape.certsrv.request.AgentApprovals) {
			com.netscape.certsrv.request.AgentApprovals o =
			(com.netscape.certsrv.request.AgentApprovals)obj;
			Enumeration e = o.elements();
			while (e.hasMoreElements()) {
				com.netscape.certsrv.request.AgentApproval approval = (com.netscape.certsrv.request.AgentApproval)e.nextElement();
				System.out.println(" " +
				key + ":" + o.getClass().getName() + "=" +
				approval.getUserName() + ";" + approval.getDate().getTime());
			}
		} else if (obj instanceof com.netscape.certsrv.authentication.AuthToken) {
			com.netscape.certsrv.authentication.AuthToken o =
			(com.netscape.certsrv.authentication.AuthToken)obj;
			Enumeration e = o.getElements();
			while (e.hasMoreElements()) {
				String k = (String)e.nextElement();
				Object ob = o.get(k);
				if (ob instanceof java.util.Date) {
					System.out.println(" " +
					key + ":" + o.getClass().getName() + "=" +
					k + ":" + ob.getClass().getName() + "=" + ((java.util.Date)ob).getTime());
                } else if (ob instanceof java.math.BigInteger[]) {
                    // Bugzilla Bug #225031 (a.k.a. - Raidzilla Bug #58356)
                    java.math.BigInteger in[] = (java.math.BigInteger[])ob;
                    String numbers = "";
                    for (int i = 0; i < in.length; i++) {
                      if (numbers.equals("")) {
                        numbers = in[i].toString();
                      } else {
                        numbers = numbers + "," + in[i].toString();
                      }
                    }
                    System.out.println(" " +
                    key + ":" + "com.netscape.certsrv.authentication.AuthToken" + "=" +
                    k + ":java.lang.String=" + numbers);
               } else if (ob instanceof String[]) {
                    // Bugzilla Bug #224763 (a.k.a. - Raidzilla Bug #57949)
                    // Bugzilla Bug #252240
                    String str[] = (String[])ob;
                    String v = "";
                    if (str != null) {
                      for (int i = 0; i < str.length; i++) {
                        if (i != 0) {
                          v += ",";
                        }
                        v += str[i];
                      }
                    }
                    System.out.println(" " +
                    key + ":" + o.getClass().getName() + "=" +
                    k + ":" + "java.lang.String" + "=" + v);
				} else {
					System.out.println(" " +
					key + ":" + o.getClass().getName() + "=" +
					k + ":" + ob.getClass().getName() + "=" + ob);
				}
			}
		} else if (obj instanceof byte[]) {
			BASE64Encoder encoder = new BASE64Encoder();
			System.out.println(" " + key + ":byte[]="+
			encoder.encode((byte[])obj));
		} else if (obj instanceof Integer[]) {
			Integer in[] = (Integer[])obj;
			for (int i = 0; i < in.length; i++) {
				System.out.println(" " + key + ":Integer[" + in.length + "," + i + "]="+ in[i]);
			}
        } else if (obj instanceof BigInteger[]) {
            // Bugzilla Bug #238779
            BigInteger in[] = (BigInteger[])obj;
            for (int i = 0; i < in.length; i++) {
                System.out.println(" " + key + ":java.math.BigInteger[" + in.length + "," + i + "]="+ in[i]);
            }
        } else if (obj instanceof String[]) {
            // Bugzilla Bug #223360 (a.k.a - Raidzilla Bug #58086)
            String str[] = (String[])obj;
            for (int i = 0; i < str.length; i++) {
                System.out.println(" " + key + ":java.lang.String[" + str.length + "," + i + "]="+ str[i]);
            }
		} else if (obj instanceof netscape.security.x509.CertificateAlgorithmId) {
			netscape.security.x509.CertificateAlgorithmId o =
			(netscape.security.x509.CertificateAlgorithmId)obj;
			ByteArrayOutputStream bos = 
				new ByteArrayOutputStream();
			o.encode(bos);
			BASE64Encoder encoder = new BASE64Encoder();
			System.out.println(" " + key + 
			":netscape.security.x509.CertificateAlgorithmId="+ 
			encoder.encode(bos.toByteArray()));
		} else if (obj instanceof netscape.security.x509.CertificateValidity) {
			netscape.security.x509.CertificateValidity o =
			(netscape.security.x509.CertificateValidity)obj;
			ByteArrayOutputStream bos = 
				new ByteArrayOutputStream();
			o.encode(bos);
			BASE64Encoder encoder = new BASE64Encoder();
			System.out.println(" " + key + 
			":netscape.security.x509.CertificateValidity="+ 
			encoder.encode(bos.toByteArray()));
        } else if (obj instanceof byte[]) {
            // Since 6.1's profile framework,
            // req_archive_options is a byte array
            BASE64Encoder encoder = new BASE64Encoder();
            System.out.println(" " + key +
            ":byte[]="+
            encoder.encode((byte[])obj));
        } else if (obj instanceof java.util.Hashtable) {
            // Bugzilla Bug #224800 (a.k.a - Raidzilla Bug #56953)
            //
            // Example:  fingerprints:java.util.Hashtable=
            //           {SHA1=[B@52513a, MD5=[B@52c4d9, MD2=[B@799ff5}
            //
            java.util.Hashtable o = (java.util.Hashtable)obj;
            BASE64Encoder encoder = new BASE64Encoder();
            Enumeration e = o.elements();
            while (e.hasMoreElements()) {
                String k = (String)e.nextElement();
                System.out.println(" " +
                key + ":" + o.getClass().getName() + "=" +
                k + "=" + encoder.encode((byte[])o.get(k)));
            }
		} else {
			System.out.println(" " +
				key + ":" + obj.getClass().getName() + "=" + 
				obj);
		}
	}
}

