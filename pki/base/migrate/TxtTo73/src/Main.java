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
//  "TxtTo71/src/Main.java" is based upon a copy "TxtTo70/src/Main.java".
//
//  Always comment any new code sections with a "CMS 7.1" header, and
//  apply these changes forward to all other "TxtTo*/src/Main.java" files
//  (including this comment header) so that these differences will only
//  appear when this file is diffed against an earlier "TxtTo*" version.
//
//  This file should always be maintained by executing the following command:
//
//      diff TxtTo70/src/Main.java TxtTo71/src/Main.java
//

import java.math.*;
import java.io.*;
import java.util.*;
import sun.misc.*;
import org.mozilla.jss.*;               // CMS 4.5 and later
import org.mozilla.jss.crypto.*;        // CMS 4.5 and later
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authentication.*;
import netscape.security.util.*;
import java.lang.reflect.*;

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
			CMS73LdifParser parser = null;
			if (args.length == 1) {
			  parser = new CMS73LdifParser(args[0]);
			} else if (args.length == 2) {
			  parser = new CMS73LdifParser(args[0], args[1]);
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

class CMS73LdifParser
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

	public CMS73LdifParser(String filename)
	{
		mFilename = filename;
	}

	public CMS73LdifParser(String filename, String errorFilename)
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
		Vector requestAttributes = null;
		while ((line = reader.readLine()) != null) { 
			if (line.startsWith(DN)) {
				dn = line;
			}
			if (line.equals(BEGIN)) {
				requestAttributes = new Vector();
				continue;
			}
			if (requestAttributes == null) {
				System.out.println(line);
				continue;
			}
			if (line.equals(END)) {
				parseAttributes(dn, requestAttributes);
				requestAttributes = null;
				continue;
			}
			if (line.startsWith(" ")) { // begining of attr
				requestAttributes.addElement(
					line.substring(1, line.length()));
			} else {
				requestAttributes.setElementAt(
					(String)
					requestAttributes.lastElement() + 
					"\n" + 
					line,
					requestAttributes.size() - 1);
			}
		} 
	}

	private byte[] encode(Object value) throws Exception 
	{ 
		ByteArrayOutputStream bos = new ByteArrayOutputStream(); 
		ObjectOutputStream os = new ObjectOutputStream(bos);

		os.writeObject(value); 
		os.close(); 
		return bos.toByteArray(); 
	}

	public void parseAttributes(String dn, Vector attrs) throws Exception
	{ 
		Hashtable hashtable = new Hashtable();
		for (int i = 0; i < attrs.size(); i++) {
			String attr = (String)attrs.elementAt(i);
			buildHashtable(dn, hashtable, attr);
		}

		ByteArrayOutputStream bos = new ByteArrayOutputStream(); 
		ObjectOutputStream os = new ObjectOutputStream(bos);
		Enumeration e = hashtable.keys();
		while (e.hasMoreElements()) {
			String key = (String)e.nextElement();
			Object value = hashtable.get(key);

			try {
			  byte data[] = null;
			  data = encode(value); 
			  os.writeObject(key); 
			  os.writeObject(data);
			} catch (Exception ex) {
			  if (mErrorPrintWriter != null) {
			    if (dn != null) {
			        mErrorPrintWriter.println(dn);
			    }
			    mErrorPrintWriter.println("Skipped " + key);
			  }
			}
		} // while
		os.writeObject(null); 
		os.close();

		// print the BASE64 encoding of the Hashtable
		BASE64Encoder encoder = new BASE64Encoder();
		String attrsStr = encoder.encodeBuffer(bos.toByteArray());		
		// trim the last "\n"
		StringBuffer buffer = null;
		attrsStr = attrsStr.trim();
		StringTokenizer st = new StringTokenizer(attrsStr, "\r\n");
		while (st.hasMoreTokens()) {
			if (buffer == null) {
				buffer = new StringBuffer();
				buffer.append(st.nextToken());
			} else {
				buffer.append("\r\n " + st.nextToken());
			}
		}

		System.out.println(REQUEST_ATTRIBUTES + " " + buffer); 
	}

	public void buildHashtable(String dn, Hashtable table, String attr) 
		throws Exception
	{ 
		// attribute format  [name]:[type]=[value]
	
		int colon = attr.indexOf(':');
		if (colon == -1) {
			if (mErrorPrintWriter != null) {
			    if (dn != null) {
			        mErrorPrintWriter.println(dn);
			    }
			    mErrorPrintWriter.println("Skipped " + attr);
			}
			return;
		}
		int equal = attr.indexOf('=');
		if (equal == -1) {
			if (mErrorPrintWriter != null) {
			    if (dn != null) {
			        mErrorPrintWriter.println(dn);
			    }
			    mErrorPrintWriter.println("Skipped " + attr);
			}
			return;
		}
		String name = null;
		String type = null;
		String value = null;
		try {
			name = attr.substring(0, colon);
			type = attr.substring(colon+1, equal);
			value = attr.substring(equal+1);
		} catch (Exception e) {
			if (mErrorPrintWriter != null) {
			    if (dn != null) {
			        mErrorPrintWriter.println(dn);
			    }
			    mErrorPrintWriter.println("Skipped " + attr);
			}
			return;
		}

		if (name.startsWith("serviceErrors")) {
			// #56953 - skip serviceErrors
			if (mErrorPrintWriter != null) {
			    if (dn != null) {
			        mErrorPrintWriter.println(dn);
			    }
			    mErrorPrintWriter.println("Skipped " + attr);
			}
			return;
		}
		if (name.startsWith("Error")) {
			// #56953 - skip serviceErrors
			if (mErrorPrintWriter != null) {
			    if (dn != null) {
			        mErrorPrintWriter.println(dn);
			    }
			    mErrorPrintWriter.println("Skipped " + attr);
			}
			return;
		}

		// To account for '47ToTxt' data files that have previously
		// been generated, ALWAYS convert 'iplanet' to 'netscape'.
		//
		//     Bugzilla Bug #224801 (a.k.a - Raidzilla Bug #56981)
		//     Bugzilla Bug #483519
		//
		String translation = null;
		if( type.startsWith( "iplanet" ) ) {
			translation = "netscape"
                        + type.substring( 7 );
			type = translation;
		} else if( type.startsWith( "com.iplanet" ) ) {
			translation = "com.netscape"
                        + type.substring( 11 );
			type = translation;
		}

		if (type.startsWith("com.netscape.certsrv.request.AgentApprovals")) {
			com.netscape.certsrv.request.AgentApprovals obj =
				(com.netscape.certsrv.request.AgentApprovals)table.get(name);
			if (obj == null) {
				obj = new com.netscape.certsrv.request.AgentApprovals();
				table.put(name, obj);
			}
			obj.addApproval(value.substring(0,value.indexOf(';')));
		} else if (type.startsWith("com.netscape.certsrv.base.ArgBlock")
               ||  type.startsWith("com.netscape.cmscore.base.ArgBlock")) {
			// CMS 6.1:  created new "com.netscape.certsrv.base.IArgBlock" and
			//           moved old "com.netscape.certsrv.base.ArgBlock"
			//           to "com.netscape.cmscore.base.ArgBlock"
			com.netscape.cmscore.base.ArgBlock obj =
				(com.netscape.cmscore.base.ArgBlock)table.get(name);
			if (obj == null) {
				// CMS 6.1:  created new "com.netscape.certsrv.base.IArgBlock" and
				//           moved old "com.netscape.certsrv.base.ArgBlock"
				//           to "com.netscape.cmscore.base.ArgBlock"
				obj = new com.netscape.cmscore.base.ArgBlock();
				table.put(name, obj);
			}
			String valuekey = value.substring(0, value.indexOf('='));
			String valuevalue = value.substring(value.indexOf('=')+1);
			obj.set(valuekey, valuevalue);
		} else if (type.startsWith("com.netscape.certsrv.authentication.AuthToken")) {
			com.netscape.certsrv.authentication.AuthToken obj =
				(com.netscape.certsrv.authentication.AuthToken)table.get(name);
			if (obj == null) {
				com.netscape.certsrv.authentication.IAuthManager mgr = 
					new DummyAuthManager();
				obj = new com.netscape.certsrv.authentication.AuthToken(mgr);
				table.put(name, obj);
			}
			String valuekey = value.substring(0, value.indexOf(':'));
			String valuetype = value.substring(value.indexOf(':')+1, value.indexOf('='));
			String valuevalue = value.substring(value.indexOf('=')+1);
			if (valuetype.equals("java.lang.String")) {
                // Processes 'java.math.BigInteger[]':
                // 
                //     Bugzilla Bug #225031 (a.k.a - Raidzilla Bug #58356)
                // 
                // Processes 'java.lang.String[]':
                // 
                //     Bugzilla Bug #224763 (a.k.a - Raidzilla Bug #57949)
                //     Bugzilla Bug #252240
                // 
				obj.set(valuekey, valuevalue);
			} else if (valuetype.equals("java.util.Date")) {
				obj.set(valuekey, new Date(Long.parseLong(valuevalue)));
			} else {
				System.err.println("ERROR AuthToken type - " + attr);
				System.exit(0);
			}
        } else if (type.startsWith("java.math.BigInteger[")) {
            // Bugzilla Bug #238779
            int size = Integer.parseInt(type.substring(type.indexOf('[')+ 1, type.indexOf(',')));
            int index = Integer.parseInt(type.substring(type.indexOf(',')+1, type.indexOf(']')));
            java.math.BigInteger objs[] = (java.math.BigInteger[])table.get(name);
            if (objs == null) {
               objs = new java.math.BigInteger[size];
               table.put(name, objs);
            }
            objs[index] = new java.math.BigInteger(value);
		} else if (type.startsWith("java.math.BigInteger")) {
			table.put(name, new java.math.BigInteger(value));
        } else if (type.startsWith("byte[]")) {
            BASE64Decoder decoder = new BASE64Decoder();
            table.put(name, decoder.decodeBuffer(value));
		} else if (type.startsWith("byte[")) {
			// byte array
			BASE64Decoder decoder = new BASE64Decoder();
			table.put(name, decoder.decodeBuffer(value));
		} else if (type.startsWith("netscape.security.x509.CertificateAlgorithmId")) {
			BASE64Decoder decoder = new BASE64Decoder();
			netscape.security.x509.CertificateAlgorithmId obj = 
				new netscape.security.x509.CertificateAlgorithmId(new ByteArrayInputStream(decoder.decodeBuffer(value)));
			table.put(name, obj);
		} else if (type.equals("netscape.security.x509.CertificateChain")) {
			BASE64Decoder decoder = new BASE64Decoder();
			netscape.security.x509.CertificateChain obj = 
				new netscape.security.x509.CertificateChain();
			ByteArrayInputStream bis = new ByteArrayInputStream(decoder.decodeBuffer(value));
			obj.decode(bis);
			table.put(name, obj);
		} else if (type.equals("netscape.security.x509.CertificateExtensions")) {
			BASE64Decoder decoder = new BASE64Decoder();
			netscape.security.x509.CertificateExtensions obj = 
				new netscape.security.x509.CertificateExtensions();
			obj.decodeEx(new ByteArrayInputStream(decoder.decodeBuffer(value)));
			// CMS 6.2:  revised method of decoding objects of type
			//           "netscape.security.x509.CertificateExtensions"
			table.put(name, obj);
		} else if (type.equals("netscape.security.x509.CertificateSubjectName")) {
			BASE64Decoder decoder = new BASE64Decoder();
			netscape.security.x509.CertificateSubjectName obj = 
				new netscape.security.x509.CertificateSubjectName(new DerInputStream(decoder.decodeBuffer(value)));
			// CMS 6.2:  revised method of decoding objects of type
			//           "netscape.security.x509.CertificateSubjectName"
			table.put(name, obj);
		} else if (type.startsWith("netscape.security.x509.CertificateValidity")) {
			BASE64Decoder decoder = new BASE64Decoder();
			netscape.security.x509.CertificateValidity obj = 
				new netscape.security.x509.CertificateValidity();
			ByteArrayInputStream bis = new ByteArrayInputStream(decoder.decodeBuffer(value));
			obj.decode(bis);
			table.put(name, obj);
		} else if (type.equals("netscape.security.x509.CertificateX509Key")) {
			BASE64Decoder decoder = new BASE64Decoder();
			netscape.security.x509.CertificateX509Key obj = 
				new netscape.security.x509.CertificateX509Key(
					new ByteArrayInputStream(decoder.decodeBuffer(value)));
			table.put(name, obj);
		} else if (type.startsWith("com.netscape.certsrv.cert.CertInfo")) {
			int size = Integer.parseInt(type.substring(type.indexOf('[')+ 1, type.indexOf(',')));
			int index = Integer.parseInt(type.substring(type.indexOf(',')+1, type.indexOf(']')));
			netscape.security.extensions.CertInfo objs[] = (netscape.security.extensions.CertInfo[])table.get(name);	
			BASE64Decoder decoder = new BASE64Decoder();
			if (objs == null) {
				objs = new netscape.security.extensions.CertInfo[size];
				table.put(name, objs);
			}
				objs[index] = new netscape.security.extensions.CertInfo();
				objs[index].decode(new ByteArrayInputStream(decoder.decodeBuffer(value)));
        } else if (type.startsWith("java.util.Hashtable")) {
            // Bugzilla Bug #224800 (a.k.a - Raidzilla Bug #56953)
            java.util.Hashtable obj = (java.util.Hashtable)table.get(name);
            if (obj == null) {
                obj = new java.util.Hashtable();
                table.put(name, obj);
            }
            BASE64Decoder decoder = new BASE64Decoder();
            String valuekey = value.substring(0, value.indexOf('='));
            String valuevalue = value.substring(value.indexOf('=')+1);
            obj.put(valuekey, decoder.decodeBuffer(valuevalue));
		} else if (type.startsWith("Integer[")) {
			int size = Integer.parseInt(type.substring(type.indexOf('[')+ 1, type.indexOf(',')));
			int index = Integer.parseInt(type.substring(type.indexOf(',')+1, type.indexOf(']')));
			Integer objs[] = (Integer[])table.get(name);	
			if (objs == null) {
			   objs = new Integer[size];
			   table.put(name, objs);
			}
			objs[index] = new Integer(value);
		} else if (type.startsWith("java.lang.Integer")) {
			table.put(name, new Integer(value));
        } else if (type.startsWith("org.mozilla.jss.asn1.INTEGER")) {
            // CMS 7.1 stores bodyPartId as INTEGER
            // CS 72. fixed the problem by storing it as String
			table.put(name, value);
		} else if (type.startsWith("com.netscape.certsrv.dbs.keydb.KeyRecord")
               ||  type.startsWith("com.netscape.cmscore.dbs.KeyRecord")) {
			com.netscape.cmscore.dbs.KeyRecord obj =
				(com.netscape.cmscore.dbs.KeyRecord)table.get(name);
			if (obj == null) {
				obj = new com.netscape.cmscore.dbs.KeyRecord();
				table.put(name, obj);
			}
			String valuekey = value.substring(0, value.indexOf(':'));
			String valuetype = value.substring(value.indexOf(':')+1, value.indexOf('='));
			String valuevalue = value.substring(value.indexOf('=')+1);
			if (valuetype.equals("java.lang.String")) {
				obj.set(valuekey, valuevalue);
			} else if (valuetype.equals("java.util.Date")) {
				obj.set(valuekey, new Date(Long.parseLong(valuevalue)));
			} else if (valuetype.equals("java.math.BigInteger")) {
				obj.set(valuekey, new java.math.BigInteger(valuevalue));
			} else if (valuetype.equals("java.lang.Integer")) {
				obj.set(valuekey, new Integer(valuevalue));
			} else if (valuetype.equals("com.netscape.certsrv.dbs.keydb.KeyState")) {
				obj.set(valuekey, com.netscape.certsrv.dbs.keydb.KeyState.toKeyState(valuevalue));
			} else if (valuetype.equals("[B")) {
				// byte array
				
				BASE64Decoder decoder = new BASE64Decoder();
				obj.set(valuekey, decoder.decodeBuffer(valuevalue));
			} else {
				System.err.println("ERROR KeyRecord type - " + attr);
				System.exit(0);
			}
		} else if (type.startsWith("java.util.Locale")) {
			// CMS 6.2:  begin checking for new type
			//           "java.util.Locale"
			table.put(name, Locale.getDefault());
		} else if (type.startsWith("com.netscape.certsrv.kra.ProofOfArchival")
               ||  type.startsWith("com.netscape.cmscore.kra.ProofOfArchival"))         {
			BASE64Decoder decoder = new BASE64Decoder();
			
			ByteArrayInputStream bis = new ByteArrayInputStream(decoder.decodeBuffer(value));
			com.netscape.certsrv.kra.ProofOfArchival obj = 
				buildPOA(decoder.decodeBuffer(value));
			table.put(name, obj);
		} else if (type.startsWith("netscape.security.x509.RevokedCertImpl")) {
			int size = Integer.parseInt(type.substring(type.indexOf('[')+ 1, type.indexOf(',')));
			int index = Integer.parseInt(type.substring(type.indexOf(',')+1, type.indexOf(']')));
			netscape.security.x509.RevokedCertImpl objs[] = (netscape.security.x509.RevokedCertImpl[])table.get(name);	
			BASE64Decoder decoder = new BASE64Decoder();
			if (objs == null) {
				objs = new netscape.security.x509.RevokedCertImpl[size];
				table.put(name, objs);
			}
			objs[index] = new netscape.security.x509.RevokedCertImpl(decoder.decodeBuffer(value));
		} else if (type.startsWith("java.lang.String[")) {
            // Bugzilla Bug #223360 (a.k.a - Raidzilla Bug #58086)
            int size = Integer.parseInt(type.substring(type.indexOf('[')+ 1, type.indexOf(',')));
            int index = Integer.parseInt(type.substring(type.indexOf(',')+1, type.indexOf(']')));
            java.lang.String objs[] = (java.lang.String[])table.get(name);
            if (objs == null) {
               objs = new java.lang.String[size];
               table.put(name, objs);
            }
            objs[index] = new java.lang.String(value);
        } else if (type.startsWith("java.lang.String")) {
			table.put(name, value);
		} else if (type.startsWith("java.util.Vector")) {
			Vector obj =
				(Vector)table.get(name);
			if (obj == null) {
				obj = new Vector();
				table.put(name, obj);
			}
			obj.addElement(value);
		} else if (type.startsWith("netscape.security.x509.X509CertImpl[")) {
			int size = Integer.parseInt(type.substring(type.indexOf('[')+ 1, type.indexOf(',')));
			int index = Integer.parseInt(type.substring(type.indexOf(',')+1, type.indexOf(']')));
			netscape.security.x509.X509CertImpl objs[] = (netscape.security.x509.X509CertImpl[])table.get(name);	
			BASE64Decoder decoder = new BASE64Decoder();
			if (objs == null) {
				objs = new netscape.security.x509.X509CertImpl[size];
				table.put(name, objs);
			}
			objs[index] = new netscape.security.x509.X509CertImpl(decoder.decodeBuffer(value));
		} else if (type.equals("netscape.security.x509.X509CertImpl")) {
			BASE64Decoder decoder = new BASE64Decoder();
			netscape.security.x509.X509CertImpl obj = 
				new netscape.security.x509.X509CertImpl(
					decoder.decodeBuffer(value));
			table.put(name, obj);
		} else if (type.startsWith("netscape.security.x509.X509CertInfo[")
               ||  type.startsWith("netscape.security.extensions.CertInfo[")) {
			// CMS 6.2:  begin checking for additional new type
			//           "netscape.security.extensions.CertInfo["
			//
			// CMS 6.1:  "netscape.security.x509.X509CertInfo"
			//           now always utilizes arrays such as
			//           "netscape.security.x509.X509CertInfo["
			int size = Integer.parseInt(type.substring(type.indexOf('[')+ 1, type.indexOf(',')));
			int index = Integer.parseInt(type.substring(type.indexOf(',')+1, type.indexOf(']')));
			netscape.security.x509.X509CertInfo objs[] = (netscape.security.x509.X509CertInfo[])table.get(name);	
			BASE64Decoder decoder = new BASE64Decoder();
			if (objs == null) {
				objs = new netscape.security.x509.X509CertInfo[size];
				table.put(name, objs);
			}
				objs[index] = new netscape.security.x509.X509CertInfo();
				objs[index].decode(new ByteArrayInputStream(decoder.decodeBuffer(value)));
		} else if (type.equals("netscape.security.x509.X509CertInfo")) {
			BASE64Decoder decoder = new BASE64Decoder();
			netscape.security.x509.X509CertInfo obj = 
				new netscape.security.x509.X509CertInfo(
					decoder.decodeBuffer(value));
			table.put(name, obj);
		} else if( type.endsWith( "Exception" ) ) {
			Class[] argClass = { String.class };   // the argument's class
			Object[] argValue = { value };         // the argument's value

			Class x = Class.forName( type );
			Constructor ctr = x.getConstructor( argClass );
			Exception e = ( Exception ) ctr.newInstance( argValue );
		} else {
			System.err.println("ERROR type - " + type + " - "+ attr);
			System.exit(0);
		}
	}

	public com.netscape.certsrv.kra.ProofOfArchival buildPOA(byte data[])
		throws Exception
	{ 
		DerInputStream dis = new DerInputStream(data); 
		DerValue seq[] = dis.getSequence(0);

		BigInteger mSerialNo = seq[0].getInteger().toBigInteger();

		// subject
		DerValue subject = seq[1];
		netscape.security.x509.X500Name mSubject = 
			new netscape.security.x509.X500Name(subject.toByteArray());

		// issuer
		DerValue issuer = seq[2];
		netscape.security.x509.X500Name mIssuer = 
			new netscape.security.x509.X500Name(issuer.toByteArray());

		// date of archival
		DerInputStream dateOfArchival = new DerInputStream(seq[3].toByteArray());
		Date mDateOfArchival = dateOfArchival.getUTCTime();
		com.netscape.certsrv.kra.ProofOfArchival obj = 
				new com.netscape.certsrv.kra.ProofOfArchival(mSerialNo,
				mSubject.toString(), mIssuer.toString(), mDateOfArchival);
		return obj;
	}
}

class DummyAuthManager implements com.netscape.certsrv.authentication.IAuthManager
{
	public String getName()
	{
		return "dummy";
	}

	public String getImplName()
	{
		return "dummy";
	}

	public IAuthToken authenticate(IAuthCredentials authCred)
	throws EMissingCredential, EInvalidCredentials, EBaseException
	{
		return null;
	}

	/**
	 * Initialize this authentication manager.
	 * @param name The name of this authentication manager instance.
	 * @param implName The name of the authentication manager plugin.
	 * @param config The configuration store for this authentication manager.
	 * @exception EBaseException If an initialization error occurred.
	 */
	public void init(String name, String implName, IConfigStore config)
	throws EBaseException
	{
	}

	public void shutdown()
	{
	}

	public String[] getRequiredCreds()
		{
		return null;
	}

	/**
	 * Get configuration parameters for this implementation.
	 * The configuration parameters returned is passed to the
	 * configuration console so configuration for instances of this
	 * implementation can be made through the console.
	 *
	 * @param implName The authentication manager plugin name.
	 * @exception EBaseException If an internal error occurred
	 */
	public String[] getConfigParams()
	throws EBaseException
	{
		return null;
	}

	/**
	 * Get the configuration store for this authentication manager.
	 * @return The configuration store of this authentication manager.
	 */
	public IConfigStore getConfigStore()
	{	
		return null;
	}
}

