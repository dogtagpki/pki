package com.netscape.cms.servlet.test;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.CharConversionException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SymmetricKey.NotExtractableException;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.osutil.OSUtil;

@SuppressWarnings("deprecation")
public class GeneratePKIArchiveOptions {
    
    public static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("GeneratePKIArchiveOptions", options);
        System.exit(1);
    }
    
    private static void log(String string) {
        // TODO Auto-generated method stub
        System.out.println(string);
    }
    
    // read in byte array
    // we must do this somewhere?
    public static byte[] read(String fname) throws IOException {
        File file = new File(fname);
        byte[] result = new byte[(int) file.length()];
        try {
            InputStream input = null;
            try {
                int totalBytesRead = 0;
                input = new BufferedInputStream(new FileInputStream(file));
                while (totalBytesRead < result.length) {
                    int bytesRemaining = result.length - totalBytesRead;
                    //input.read() returns -1, 0, or more :
                    int bytesRead = input.read(result, totalBytesRead, bytesRemaining);
                    if (bytesRead > 0) {
                        totalBytesRead = totalBytesRead + bytesRead;
                    }
                }
            } finally {
                input.close();
            }
        } catch (Exception e) {
            throw new IOException(e);
        }

        return result;
    }
    
    public static void write(byte[] aInput, String outFile) throws IOException {
        try {
            OutputStream output = null;
            try {
                output = new BufferedOutputStream(new FileOutputStream(outFile));
                output.write(aInput);
            } finally {
                output.close();
            }
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
    
    private static void write_file(String data, String outFile) throws IOException {
        FileWriter fstream = new FileWriter(outFile);
        BufferedWriter out = new BufferedWriter(fstream);
        out.write(data);
        //Close the output stream
        out.close();
    }

    public static void main(String args[]) throws InvalidKeyException, CertificateEncodingException,
            CharConversionException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            IllegalStateException, TokenException, IOException, IllegalBlockSizeException, BadPaddingException,
            InvalidBERException, NotExtractableException {
        String token_pwd = null;
        String db_dir = "./";
        String out_file = "./options.out";
        String transport_file = "./transport.crt";
        String key_file = "./symkey.out";
        String passphrase = null;
        boolean passphraseMode = false;

        // parse command line arguments
        Options options = new Options();
        options.addOption("w", true, "Token password (required)");
        options.addOption("d", true, "Directory for tokendb");
        options.addOption("p", true, "Passphrase");
        options.addOption("t", true, "File with transport cert");
        options.addOption("o", true, "Output file");
        options.addOption("k", true, "Key file");
        
        try {
            CommandLineParser parser = new PosixParser();
            CommandLine cmd = parser.parse(options, args);
            
            if (cmd.hasOption("p")) {
                passphrase = cmd.getOptionValue("p");
                passphraseMode = true;
            }
            
            if (cmd.hasOption("o")) {
                out_file = cmd.getOptionValue("o");
            }
            
            if (cmd.hasOption("k")) {
                key_file = cmd.getOptionValue("k");
            }
            
            if (cmd.hasOption("t")) {
                transport_file = cmd.getOptionValue("t");
            }
            
            if (cmd.hasOption("w")) {
                token_pwd = cmd.getOptionValue("w");
            } else {
                System.err.println("Error: no token password provided");
                usage(options);
            }

            if (cmd.hasOption("d")) {
                db_dir = cmd.getOptionValue("d");
            }

        } catch (ParseException e) {
            System.err.println("Error in parsing command line options: " + e.getMessage());
            usage(options);
        }

        // used for crypto operations
        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        IVParameterSpec ivps = new IVParameterSpec(iv);
        CryptoManager manager = null;
        CryptoToken token = null;

        // used for wrapping to send data to DRM
        byte[] tcert = read(transport_file);
        String transportCert = com.netscape.osutil.OSUtil.BtoA(tcert);

        // Initialize token
        try {
            CryptoManager.initialize(db_dir);
        } catch (AlreadyInitializedException e) {
            // it is ok if it is already initialized 
        } catch (Exception e) {
            log("INITIALIZATION ERROR: " + e.toString());
            System.exit(1);
        }

        // log into token
        try {
            manager = CryptoManager.getInstance();
            token = manager.getInternalKeyStorageToken();
            Password password = new Password(token_pwd.toCharArray());
            try {
                token.login(password);
            } catch (Exception e) {
                log("login Exception: " + e.toString());
                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            }
        } catch (Exception e) {
            log("Exception in logging into token:" + e.toString());
        }
        
        // Data to be archived
        SymmetricKey vek = null;
        if (!passphraseMode) {
            vek = CryptoUtil.generateKey(token, KeyGenAlgorithm.DES3);
            // store vek in file
            write_file(OSUtil.BtoA(vek.getKeyData()), key_file);
        }

        byte[] encoded = null;
        
        if (passphraseMode) {
            encoded = CryptoUtil.createPKIArchiveOptions(manager, token, transportCert, null, passphrase, 
                    KeyGenAlgorithm.DES3, ivps);
        } else {
            encoded = CryptoUtil.createPKIArchiveOptions(manager, token, transportCert, vek, null, 
                    KeyGenAlgorithm.DES3, ivps);
        }
        
        // write encoded to file
        write_file(OSUtil.BtoA(encoded), out_file);

    }
}
