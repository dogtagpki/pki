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
//  "47ToTxt/src/Main.java" is based upon a copy "42SP2ToTxt/src/Main.java"
//  with additional material provided from "45ToTxt/src/Main.java".
//
//  Always comment any new code sections with a "CMS 4.7" header, and
//  apply these changes forward to all other "*ToTxt/src/Main.java" files
//  (including this comment header) so that these differences will only
//  appear when this file is diffed against an earlier "*ToTxt" version.
//
//  This file should always be maintained by executing the following commands:
//
//      diff 42SP2ToTxt/src/Main.java 47ToTxt/src/Main.java
//      diff 45ToTxt/src/Main.java 47ToTxt/src/Main.java
//
//      NOTE:  The "47ToTxt/src/Main.java" file will differ substantially
//             from the "42SP2ToTxt/src/Main.java" and "45ToTxt/src/Main.java"
//             files upon which it was based due to the changes that were
//             necessary to change "iplanet" to "netscape".
//

import java.io.*;
import java.math.*;
import java.util.*;
import sun.misc.*;
import org.mozilla.jss.*;               // CMS 4.5 and later
import org.mozilla.jss.crypto.*;        // CMS 4.5 and later
import iplanet.security.util.*;

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
				new iplanet.security.provider.CMS(), 0); 
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
			CMS47LdifParser parser = null;
			if (args.length == 1) {
			  parser = new CMS47LdifParser(args[0]);
			} else if (args.length == 2) {
			  parser = new CMS47LdifParser(args[0], args[1]);
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

class CMS47LdifParser
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

	public CMS47LdifParser(String filename)
	{
		mFilename = filename;
	}

	public CMS47LdifParser(String filename, String errorFilename)
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
		} else if (obj instanceof iplanet.security.x509.CertificateX509Key) {
			iplanet.security.x509.CertificateX509Key o =
				(iplanet.security.x509.CertificateX509Key)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.CertificateX509Key" + "=" + 
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof iplanet.security.x509.CertificateSubjectName) {
			iplanet.security.x509.CertificateSubjectName o =
				(iplanet.security.x509.CertificateSubjectName)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.CertificateSubjectName" + "=" +
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof iplanet.security.x509.CertificateExtensions) {
			iplanet.security.x509.CertificateExtensions o =
				(iplanet.security.x509.CertificateExtensions)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.CertificateExtensions" + "=" +
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof iplanet.security.x509.X509CertInfo) {
			iplanet.security.x509.X509CertInfo o =
				(iplanet.security.x509.X509CertInfo)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.X509CertInfo" + "=" +
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof iplanet.security.x509.X509CertImpl) {
			iplanet.security.x509.X509CertImpl o =
				(iplanet.security.x509.X509CertImpl)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.X509CertImpl" + "=" + 
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof iplanet.security.x509.CertificateChain) {
			iplanet.security.x509.CertificateChain o =
				(iplanet.security.x509.CertificateChain)obj;
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.CertificateChain" + "=" + 
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof iplanet.security.x509.X509CertImpl[]) {
			iplanet.security.x509.X509CertImpl o[] =
				(iplanet.security.x509.X509CertImpl[])obj;
			for (int i = 0; i < o.length; i++) {
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o[i].encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.X509CertImpl" +"["+o.length+","+i+"]" + "=" + 
				encoder.encode(bos.toByteArray()));
			}
		} else if (obj instanceof iplanet.security.x509.X509CertInfo[]) {
			iplanet.security.x509.X509CertInfo o[] =
				(iplanet.security.x509.X509CertInfo[])obj;
			for (int i = 0; i < o.length; i++) {
				ByteArrayOutputStream bos = 
					new ByteArrayOutputStream();
				o[i].encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.X509CertInfo" + "["+o.length + "," + i+"]"+"=" + 
				encoder.encodeBuffer(bos.toByteArray()));
			}
		} else if (obj instanceof iplanet.security.x509.RevokedCertImpl[]) {
			iplanet.security.x509.RevokedCertImpl o[] =
				(iplanet.security.x509.RevokedCertImpl[])obj;
			for (int i = 0; i < o.length; i++) {
				DerOutputStream bos = 
					new DerOutputStream();
				o[i].encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "netscape.security.x509.RevokedCertImpl" +"["+o.length+","+i+"]" + "=" + 
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
		} else if (obj instanceof com.iplanet.certsrv.base.ArgBlock) {
			com.iplanet.certsrv.base.ArgBlock o =
			(com.iplanet.certsrv.base.ArgBlock)obj;
			Enumeration e = o.elements();
			while (e.hasMoreElements()) {
				String k = (String)e.nextElement();
				System.out.println(" " +
				key + ":" + "com.netscape.certsrv.base.ArgBlock" + "=" +
				k + "=" +(String)o.get(k));
			}
		} else if (obj instanceof com.iplanet.certsrv.dbs.keydb.KeyRecord) {
			com.iplanet.certsrv.dbs.keydb.KeyRecord o =
			(com.iplanet.certsrv.dbs.keydb.KeyRecord)obj;
			Enumeration e = o.getElements();
			while (e.hasMoreElements()) {
				String k = (String)e.nextElement();
				Object ob = o.get(k);
				if (ob != null) {
				if (ob instanceof java.util.Date) {
					System.out.println(" " +
					key + ":" + "com.netscape.certsrv.dbs.keydb.KeyRecord" + "=" +
					k + ":" + ob.getClass().getName() + "=" + ((java.util.Date)ob).getTime());
				} else if (ob instanceof byte[]) {
					BASE64Encoder encoder = new BASE64Encoder();
					System.out.println(" " +
					key + ":" + "com.netscape.certsrv.dbs.keydb.KeyRecord" + "=" +
					k + ":" + ob.getClass().getName() + "=" + encoder.encode((byte[])ob));

				} else {
					System.out.println(" " +
					key + ":" + "com.netscape.certsrv.dbs.keydb.KeyRecord" + "=" +
					k + ":" + ob.getClass().getName() + "=" + ob);
				}
				}
			}
		} else if (obj instanceof com.iplanet.certsrv.kra.ProofOfArchival) {
			com.iplanet.certsrv.kra.ProofOfArchival o =
				(com.iplanet.certsrv.kra.ProofOfArchival)obj;
				DerOutputStream bos = 
					new DerOutputStream();
				o.encode(bos);
				BASE64Encoder encoder = new BASE64Encoder();
				System.out.println(" " +
				key + ":" + "com.netscape.certsrv.kra.ProofOfArchival" + "=" + 
				encoder.encode(bos.toByteArray()));
		} else if (obj instanceof com.iplanet.certsrv.request.AgentApprovals) {
			com.iplanet.certsrv.request.AgentApprovals o =
			(com.iplanet.certsrv.request.AgentApprovals)obj;
			Enumeration e = o.elements();
			while (e.hasMoreElements()) {
				com.iplanet.certsrv.request.AgentApproval approval = (com.iplanet.certsrv.request.AgentApproval)e.nextElement();
				System.out.println(" " +
				"com.netscape.certsrv.request.AgentApprovals" + ":" + "com.netscape.certsrv.request.AgentApprovals" + "=" +
				approval.getUserName() + ";" + approval.getDate().getTime());
			}
		} else if (obj instanceof com.iplanet.certsrv.authentication.AuthToken) {
			com.iplanet.certsrv.authentication.AuthToken o =
			(com.iplanet.certsrv.authentication.AuthToken)obj;
			Enumeration e = o.getElements();
			while (e.hasMoreElements()) {
				String k = (String)e.nextElement();
				Object ob = o.get(k);
				if (ob instanceof java.util.Date) {
					System.out.println(" " +
					key + ":" + "com.netscape.certsrv.authentication.AuthToken" + "=" +
					k + ":" + ob.getClass().getName() + "=" + ((java.util.Date)ob).getTime());
               } else if (ob instanceof String[]) {
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
					key + ":" + "com.netscape.certsrv.authentication.AuthToken" + "=" +
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
            BigInteger in[] = (BigInteger[])obj;
            for (int i = 0; i < in.length; i++) {
                System.out.println(" " + key + ":java.math.BigInteger[" + in.length + "," + i + "]="+ in[i]);
            }
		} else if (obj instanceof iplanet.security.x509.CertificateAlgorithmId) {
			iplanet.security.x509.CertificateAlgorithmId o =
			(iplanet.security.x509.CertificateAlgorithmId)obj;
			ByteArrayOutputStream bos = 
				new ByteArrayOutputStream();
			o.encode(bos);
			BASE64Encoder encoder = new BASE64Encoder();
			System.out.println(" " + key + 
			":netscape.security.x509.CertificateAlgorithmId="+ 
			encoder.encode(bos.toByteArray()));
		} else if (obj instanceof iplanet.security.x509.CertificateValidity) {
			iplanet.security.x509.CertificateValidity o =
			(iplanet.security.x509.CertificateValidity)obj;
			ByteArrayOutputStream bos = 
				new ByteArrayOutputStream();
			o.encode(bos);
			BASE64Encoder encoder = new BASE64Encoder();
			System.out.println(" " + key + 
			":netscape.security.x509.CertificateValidity="+ 
			encoder.encode(bos.toByteArray()));
		} else {
			System.out.println(" " +
				key + ":" + obj.getClass().getName() + "=" + 
				obj);
		}
	}
}

