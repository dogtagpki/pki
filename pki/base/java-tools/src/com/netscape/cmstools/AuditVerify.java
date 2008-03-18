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


import java.io.*;
import java.util.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.util.Base64InputStream;
import java.security.*;
import java.security.interfaces.*;

/**
 * Tool for verifying signed audit logs
 * 
 * @version $Revision: 14569 $, $Date: 2007-05-01 10:50:46 -0700 (Tue, 01 May 2007) $
 */
public class AuditVerify {

    private static void usage() {
        System.out.println("Usage: AuditVerify -d <dbdir> -n <signing certificate nickname> -a <log list file> [-P <cert/key db prefix>] [-v]");
        System.exit(1);
    }

    public static final String CRYPTO_PROVIDER = "Mozilla-JSS";

    public static byte[] base64decode(String input) throws Exception {
        return com.netscape.osutil.OSUtil.AtoB(input);
    }

    // We always sign 0x0a as the line separator, regardless of what
    // line separator characters are used in the log file. This helps
    // signature verification be platform-independent.
    private static final byte LINE_SEP_BYTE = 0x0a;

    private static void output(int linenum, String mesg) throws IOException {
        System.out.println("Line " + linenum + ": " + mesg);
    }

    private static void writeFile(String curfileName) {
        System.out.println("======\nFile: " + curfileName + "\n======");
    }

    private static void writeSigStatus(int linenum, String sigStartFile,
        int sigStartLine, String sigStopFile, int sigStopLine, String mesg)
            throws IOException
    {
        output(linenum, mesg + ": signature of " + sigStartFile + ":" +
            sigStartLine + " to " + sigStopFile + ":" + sigStopLine);
    }

    private static class PrefixFilter implements FilenameFilter {
        private String prefix;
        public PrefixFilter(String prefix) {
            this.prefix = prefix;
        }
        public boolean accept(File dir, String name) {
            // look for <prefix>cert* in this directory
            return( name.indexOf(prefix + "cert") != -1 );
        }
    }

    public static boolean validPrefix(String configDir, String prefix)
        throws IOException
    {
        File dir = new File(configDir);
        if( ! dir.isDirectory() ) {
            System.out.println("ERROR: \"" + dir + "\" is not a directory");
            usage();
        }

        String matchingFiles[] = dir.list( new PrefixFilter(prefix) );

        // prefix may be valid if at least one file matched the pattern
        return (matchingFiles.length > 0);
    }


    public static void main(String args[]) {
      try {

        String dbdir = null;
        String logListFile = null;
        String signerNick = null;
        String prefix = null;
        boolean verbose = false;

        for(int i = 0; i < args.length; ++i) {
            if( args[i].equals("-d") ) {
                if( ++i >= args.length ) usage();
                dbdir = args[i];
            } else if( args[i].equals("-a") ) {
                if( ++i >= args.length ) usage();
                logListFile = args[i];
            } else if( args[i].equals("-n") ) {
                if( ++i >= args.length ) usage();
                signerNick = args[i];
            } else if( args[i].equals("-P") ) {
                if( ++i >= args.length ) usage();
                prefix = args[i];
            } else if( args[i].equals("-v") ) {
                verbose = true;
            } else {
                System.out.println("Unrecognized argument(" + i + "): "
                    + args[i]);
                usage();
            }
        }
        if( dbdir == null || logListFile == null || signerNick == null) {
            System.out.println("Argument omitted");
            usage();
        }

        // get list of log files
        Vector logFiles = new Vector();
        BufferedReader r = new BufferedReader(new FileReader(logListFile));
        String listLine;
        while( (listLine = r.readLine()) != null ) {
            StringTokenizer tok = new StringTokenizer(listLine, ",");
            while( tok.hasMoreElements() ) {
                logFiles.addElement( ((String)tok.nextElement()).trim());
            }
        }
        if( logFiles.size() == 0 ) {
            System.out.println("Error: no log files listed in " + logListFile);
            System.exit(1);
        }

        // initialize crypto stuff
        if( prefix == null ) {
            if( ! validPrefix(dbdir, "")) {
                System.out.println("ERROR: \"" + dbdir +
                    "\" does not contain any security databases");
                usage();
            }
            CryptoManager.initialize(dbdir);
        } else {
            if( ! validPrefix(dbdir, prefix) ) {
                System.out.println("ERROR: \"" + prefix +
                    "\" is not a valid prefix");
                usage();
            }
            CryptoManager.initialize(
                new CryptoManager.InitializationValues(dbdir, prefix, prefix,
                        "secmod.db")
            );
        }
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate signerCert = cm.findCertByNickname(signerNick);
        
        // verify signer's certificate
        if( ! cm.isCertValid(signerNick, true,
                        CryptoManager.CertUsage.EmailSigner) )
        {
            System.out.println("Error: signing certificate is not valid");
            System.exit(1);
        }

        PublicKey pubk = signerCert.getPublicKey();
        String sigAlgorithm=null;
        if( pubk instanceof RSAPublicKey ) {
            sigAlgorithm = "SHA-1/RSA";
        } else if( pubk instanceof DSAPublicKey ) {
            sigAlgorithm = "SHA-1/DSA";
        } else {
            System.out.println("Error: unknown key type: " +
                pubk.getAlgorithm());
            System.exit(1);
        }
        Signature sig = Signature.getInstance(sigAlgorithm, CRYPTO_PROVIDER);
        sig.initVerify(pubk);

        int goodSigCount = 0;
        int badSigCount = 0;

        int lastFileWritten = -1;

        int sigStartLine = 1;
        int sigStopLine = 1;
        String sigStartFile = (String) logFiles.elementAt(0);
        String sigStopFile = null;
        int signedLines = 1;

        boolean lastLineWasSig = false;

        for( int curfile = 0; curfile < logFiles.size(); ++curfile) {
            String curfileName = (String) logFiles.elementAt(curfile);
            BufferedReader br = new BufferedReader(new FileReader(curfileName));

            if( verbose ) {
                writeFile(curfileName);
                lastFileWritten = curfile;
            }

            String curLine;
            int linenum = 0;
            while( (curLine = br.readLine()) != null ) {
                ++linenum;
                if( curLine.indexOf("AUDIT_LOG_SIGNING") != -1 ) {
                    if( curfile == 0 && linenum == 1 ) {
                        // Ignore the first signature of the first file,
                        // since it signs data we don't have access to.
                        if( verbose ) {
                            output(linenum,
                                "Ignoring first signature of log series");
                        }
                    } else {
                        int sigStart = curLine.indexOf("sig: ") + 5;
                        if( sigStart < 5 ) {
                            output(linenum, "INVALID SIGNATURE");
                            ++badSigCount;
                        } else {
                            byte[] logSig =
                                base64decode(curLine.substring(sigStart));
    
                            // verify the signature
                            if( sig.verify(logSig) ) {
                                // signature verifies correctly
                                if( verbose ) {
                                    writeSigStatus(linenum, sigStartFile,
                                        sigStartLine, sigStopFile, sigStopLine,
                                        "verification succeeded");
                                }
                                ++goodSigCount;
                            } else {
                                if( lastFileWritten < curfile ) {
                                    writeFile(curfileName);
                                    lastFileWritten = curfile;
                                }
                                writeSigStatus(linenum, sigStartFile,
                                        sigStartLine, sigStopFile, sigStopLine,
                                        "VERIFICATION FAILED");
                                ++badSigCount;
                            }
                        }
                        sig.initVerify(pubk);
                        signedLines = 0;
                        sigStartLine = linenum;
                        sigStartFile = curfileName;
                    }
                }

                byte[] lineBytes = curLine.getBytes("UTF-8");
                sig.update(lineBytes);
                sig.update(LINE_SEP_BYTE);
                ++signedLines;
                sigStopLine = linenum;
                sigStopFile = curfileName;
            }

        }

        // Make sure there were no unsigned log entries at the end.
        // The first signed line is the previous signature, but anything
        // more than that is data.
        if( signedLines > 1 ) {
            System.out.println(
                "ERROR: log entries after " + sigStartFile
                + ":" + sigStartLine + " are UNSIGNED");
            badSigCount++;
        }

        System.out.println("\nVerification process complete.");
        System.out.println("Valid signatures: " + goodSigCount);
        System.out.println("Invalid signatures: " + badSigCount);

        if( badSigCount > 0 ) {
            System.exit(2);
        } else {
            System.exit(0);
        }

      } catch(FileNotFoundException fnfe) {
        System.out.println(fnfe);
      } catch(ObjectNotFoundException onfe) {
        System.out.println("ERROR: certificate not found");
      } catch(Exception e) {
        e.printStackTrace();
      }

        System.out.println("Verification process FAILED.");
        System.exit(1);
    }
}
