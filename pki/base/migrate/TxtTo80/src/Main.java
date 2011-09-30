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
// (C) 2009 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
//
//  "TxtTo80/src/Main.java" is based upon a copy "TxtTo80/src/Main.java".
//
//  Always comment any new code sections with a "CS 8.0" header, and
//  apply these changes forward to all other "TxtTo*/src/Main.java" files
//  (including this comment header) so that these differences will only
//  appear when this file is diffed against an earlier "TxtTo*" version.
//
//  This file should always be maintained by executing the following command:
//
//      diff TxtTo73/src/Main.java TxtTo80/src/Main.java
//

import java.math.*;
import java.io.*;
import java.util.*;
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
			CS80LdifParser parser = null;
			if (args.length == 1) {
			  parser = new CS80LdifParser(args[0]);
			} else if (args.length == 2) {
			  parser = new CS80LdifParser(args[0], args[1]);
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

class CS80LdifParser
{
	// constants
	private static final String DN = 
		"dn:";
	// Directory Servers in CS 8.0 and later use "extdata-"
	private static final String extAttrPrefix =
		"extdata-";
	private static final String BEGIN = 
		"--- BEGIN ATTRIBUTES ---";
	private static final String END = 
		"--- END ATTRIBUTES ---";

	// variables
	private String mFilename = null;
	private String mErrorFilename = null;
	private PrintWriter mErrorPrintWriter = null;

	public CS80LdifParser(String filename)
	{
		mFilename = filename;
	}

	public CS80LdifParser(String filename, String errorFilename)
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
				// Since we are not in the midst of a Request Attribute,
				// simply print out the line.
				System.out.println(line);

				// New in CS 8.0:
				if( line.equals( "objectClass: request" ) ) {
					// Since Request Objects now contain individual undefined
					// schema attributes (rather than a single serialized blob),
					// we disable schema checking to allow them to be stored as
					// Multi-Value strings by adding an "extensibleObject"
					// objectclass to each Request Object entry.
					System.out.println( "objectClass: extensibleObject" );
				}
				continue;
			}
			if (line.equals(END)) {
				parseAttributes(dn, requestAttributes);
				requestAttributes = null;
				continue;
			}
			if (line.startsWith(" ")) { // beginning of attr
				requestAttributes.addElement(
					line.substring(1, line.length()));
			} else {
				// #737216 - skip unnecessary empty lines in attributes
				if (line.trim().length() == 0) continue;
				requestAttributes.setElementAt(
					(String)
					requestAttributes.lastElement() + 
					"\n" + 
					line,
					requestAttributes.size() - 1);
			}
		} 
	}

	public String getKey( String dn, String attr )
	{
		String key = null;

		int colon = attr.indexOf( ':' );
		if (colon == -1) {
			return key;
		}

		int equal = attr.indexOf( '=' );
		if( equal == -1 ) {
			return key;
		}

		key = attr.substring( 0, colon );
		if( key.startsWith( "serviceErrors" ) ) {
			// #56953 - skip serviceErrors
			return key;
		}

		if( key.startsWith( "Error" ) ) {
			// #56953 - skip Error
			return key;
		}

		return key;
	} 

	public void parseAttributes(String dn, Vector attrs) throws Exception
	{ 
		for( int i = 0; i < attrs.size(); i++ ) {
			String attr = ( String ) attrs.elementAt( i );
			try {
				translateAttributes( dn, attr );
			} catch( Exception e ) {
				if( mErrorPrintWriter != null ) {
					mErrorPrintWriter.println( dn );
				}
				String key = getKey( dn, attr );
				if( key != null ) {
					mErrorPrintWriter.println( "Skipped " + key );
				}
			}
		}
	}

	/*************************************************************************/
	/* The following two functions:                                          */
	/*                                                                       */
	/*   protected boolean isAlphaNum(char in) {}                            */
	/*                                                                       */
	/*   public String encodeKey(String key) {}                              */
	/*                                                                       */
	/* were copied from the private class called:                            */
	/*                                                                       */
	/*    class ExtAttrDynMapper implements IDBDynAttrMapper {}              */
	/*                                                                       */
	/* in the file called:                                                   */
	/*                                                                       */
	/*   pki/base/common/src/com/netscape/cmscore/request/RequestRecord.java */
	/*                                                                       */
	/*************************************************************************/

	protected boolean isAlphaNum(char in) {
		if ((in >= 'a') && (in <= 'z')) {
			return true;
		}
		if ((in >= 'A') && (in <= 'Z')) {
			return true;
		}
		if ((in >= '0') && (in <= '9')) {
			return true;
		}
		return false;
	}

	/**
	 * Encoded extdata keys for storage in LDAP.
	 *
	 * The rules for encoding are trickier than decoding.  We want to allow
	 * '-' by itself to be stored in the database (for the common case of keys
	 * like 'Foo-Bar'.  Therefore we are using '--' as the encoding character.
	 * The rules are:
	 * 1) All characters [^-a-zA-Z0-9] are encoded as --XXXX where XXXX is the
	 *    hex representation of the digit.
	 * 2) [a-zA-Z0-9] are always passed through unencoded
	 * 3) [-] is passed through as long as it is preceded and followed
	 *    by [a-zA-Z0-9] (or if it's at the beginning/end of the string)
	 * 4) If [-] is preceded or followed by [^a-zA-Z0-9] then
	 *    the - as well as all following [^a-zA-Z0-9] characters are encoded
	 *    as --XXXX.
	 *
	 * This routine tries to be as efficient as possible with StringBuffer and
	 * large copies.  However, the encoding unfortunately requires several
	 * objects to be allocated.
	 *
	 * @param key The key to encode
	 * @return  The encoded key
	 */
	public String encodeKey(String key) {
		StringBuffer output = null;
		char[] input = key.toCharArray();
		int startCopyIndex = 0;

		int index = 0;
		while (index < input.length) {
			if (! isAlphaNum(input[index])) {
				if ((input[index] == '-') &&
					((index + 1) < input.length) &&
					(isAlphaNum(input[index + 1]))) {
					index += 2;
				} else if ((input[index] == '-') &&
						   ((index + 1) == input.length)) {
					index += 1;
				} else {
					if (output == null) {
						output = new StringBuffer(input.length + 5);
					}
					output.append(input, startCopyIndex, index - startCopyIndex);
					while ( (index < input.length) &&
							(! isAlphaNum(input[index])) ) {
						output.append("--");
						String hexString = Integer.toHexString(input[index]);
						int padding = 4 - hexString.length();
						while (padding > 0) {
							output.append('0');
							padding--;
						}
						output.append(hexString);
						index++;
					}
					startCopyIndex = index;
				}
			} else {
				index++;
			}
		}

		if (output == null) {
			return key;
		} else {
			output.append(input, startCopyIndex, index - startCopyIndex);
			return output.toString();
		}
	}

	public String formatData( String data ) {
		StringBuffer output = null;
		char[] input = data.toCharArray();
		int startCopyIndex = 0;

		// Every string buffer has a capacity. As long as the length of the
		// character sequence contained in the string buffer does not exceed
		// the capacity, it is not necessary to allocate a new internal buffer
		// array. If the internal buffer overflows, it is automatically made
		// larger. 
		//
		// Start out with an output buffer at least as big as the input buffer.
		output = new StringBuffer( input.length );

		int index = 0;
		while( index < input.length ) {
			if( input[index] != '\n' ) {
				output.append( input[index] );
			} else {
				output.append( input[index] );
				if( index != ( input.length - 1 ) ) {
					// Place an initial space after each carriage return
					// with the exception of the last one
					output.append( ' ' );
				}
			}

			index++;
		}

		return( output.toString() );
	}

	public void translateAttributes( String dn, String attr ) 
		throws Exception
	{
		// attribute format  [key]:[type]=[data]
	
		int colon = attr.indexOf( ':' );
		if( colon == -1 ) {
			if( mErrorPrintWriter != null ) {
			    if( dn != null ) {
			        mErrorPrintWriter.println( dn );
			    }
			    mErrorPrintWriter.println( "Skipped " + attr );
			}
			return;
		}
		int equal = attr.indexOf( '=' );
		if( equal == -1 ) {
			if( mErrorPrintWriter != null ) {
			    if( dn != null ) {
			        mErrorPrintWriter.println( dn );
			    }
			    mErrorPrintWriter.println( "Skipped " + attr );
			}
			return;
		}

		String key = attr.substring( 0, colon );
		String type = attr.substring( colon + 1, equal );
		String data = attr.substring( equal + 1 );

		if( key.startsWith( "serviceErrors" ) ) {
			// #56953 - skip serviceErrors
			if( mErrorPrintWriter != null ) {
			    if( dn != null ) {
			        mErrorPrintWriter.println( dn );
			    }
			    mErrorPrintWriter.println( "Skipped " + attr );
			}
			return;
		}

		if( key.startsWith( "Error" ) ) {
			// #56953 - skip serviceErrors
			if( mErrorPrintWriter != null ) {
			    if( dn != null ) {
			        mErrorPrintWriter.println( dn );
			    }
			    mErrorPrintWriter.println( "Skipped " + attr );
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

		if( type.startsWith( "com.netscape.certsrv.request.AgentApprovals" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "com.netscape.certsrv.base.ArgBlock" )
               ||  type.startsWith( "com.netscape.cmscore.base.ArgBlock" ) ) {
			// CMS 6.1:  created new "com.netscape.certsrv.base.IArgBlock" and
			//           moved old "com.netscape.certsrv.base.ArgBlock"
			//           to "com.netscape.cmscore.base.ArgBlock"
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "com.netscape.certsrv.authentication.AuthToken" ) ) {
            // Processes 'java.math.BigInteger[]':
            // 
            //     Bugzilla Bug #225031 (a.k.a - Raidzilla Bug #58356)
            // 
            // Processes 'java.lang.String[]':
            // 
            //     Bugzilla Bug #224763 (a.k.a - Raidzilla Bug #57949)
            //     Bugzilla Bug #252240
            // 
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "java.math.BigInteger[" ) ) {
            // Bugzilla Bug #238779
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "java.math.BigInteger" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "byte[]" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "byte[" ) ) {
			// byte array
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "netscape.security.x509.CertificateAlgorithmId" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.equals( "netscape.security.x509.CertificateChain" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.equals( "netscape.security.x509.CertificateExtensions" ) ) {
			// XXX - "db2ldif" appears dumps these as ":" values, but they
			//       always appear as "::" base-64 encoded values?
			// CMS 6.2:  revised method of decoding objects of type
			//           "netscape.security.x509.CertificateExtensions"
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.equals( "netscape.security.x509.CertificateSubjectName" ) ) {
			// CMS 6.2:  revised method of decoding objects of type
			//           "netscape.security.x509.CertificateSubjectName"
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "netscape.security.x509.CertificateValidity" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.equals( "netscape.security.x509.CertificateX509Key" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "com.netscape.certsrv.cert.CertInfo" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
        } else if (type.startsWith("java.util.Hashtable")) {
			// Bugzilla Bug #224800 (a.k.a - Raidzilla Bug #56953)
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "Integer[" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "java.lang.Integer" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "org.mozilla.jss.asn1.INTEGER" ) ) {
			// CS 7.1 stores bodyPartId as INTEGER
			// CS 7.2 fixed the problem by storing it as String
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "com.netscape.certsrv.dbs.keydb.KeyRecord" )
               ||  type.startsWith( "com.netscape.cmscore.dbs.KeyRecord" ) ) {
			// Bugzilla Bug #508191 - These only apply to KRA; and in CS 8.0,
			//                        since KRA requests only need to refer
			//                        to the actual "keyRecord" referenced
			//                        by the "keySerialNumber" data,
			//                        all other "KeyRecord" request data is 
			//                        ignored, since it is already stored
			//                        in the actual "keyRecord".
			if( data.startsWith( "keySerialNumber" ) ) {
				String keySerialNumber = data.substring( data.indexOf( "=" ) + 1 );
				System.out.println( extAttrPrefix +
									encodeKey( key.toLowerCase() ) + ": " +
									formatData( keySerialNumber ) );
			}
		} else if( type.startsWith( "java.util.Locale" ) ) {
			// CMS 6.2:  begin checking for new type
			//           "java.util.Locale"
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "com.netscape.certsrv.kra.ProofOfArchival" )
               ||  type.startsWith( "com.netscape.cmscore.kra.ProofOfArchival" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "netscape.security.x509.RevokedCertImpl" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "java.lang.String[" ) ) {
            // Bugzilla Bug #223360 (a.k.a - Raidzilla Bug #58086)
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
        } else if (type.startsWith("java.lang.String")) {
			// Examples:
			//
			//     key.equals( "publickey" )
			//     key.equals( "cert_request" )
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
									formatData( data ) );
		} else if( type.startsWith( "java.util.Vector" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "netscape.security.x509.X509CertImpl[" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.equals( "netscape.security.x509.X509CertImpl" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.startsWith( "netscape.security.x509.X509CertInfo[" )
               ||  type.startsWith( "netscape.security.extensions.CertInfo[" ) )
        {
			// CMS 6.2:  begin checking for additional new type
			//           "netscape.security.extensions.CertInfo["
			//
			// CMS 6.1:  "netscape.security.x509.X509CertInfo"
			//           now always utilizes arrays such as
			//           "netscape.security.x509.X509CertInfo["
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.equals( "netscape.security.x509.X509CertInfo" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else if( type.endsWith( "Exception" ) ) {
			System.out.println( extAttrPrefix + encodeKey( key ) + ": " +
								formatData( data ) );
		} else {
			System.err.println( "ERROR type - " + type + " - "+ attr );
			System.exit( 0 );
		}
	}
}

