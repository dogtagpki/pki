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

package com.netscape.symkey;


import org.mozilla.jss.pkcs11.PK11SymKey;


/**
 * This object contains the OS independent interfaces. 
 */
public class SessionKey
{
    static boolean tryLoad( String filename )
    {
        try {
            System.load( filename );
        } catch( Exception e ) {
            return false;
        } catch( UnsatisfiedLinkError e ) {
            return false;
        }

        return true;
    }

    // Load native library
    static {
        boolean mNativeLibrariesLoaded = false;
        String os = System.getProperty( "os.name" );
        if( ( os.equals( "Linux" ) ) ) {
            // Check for 64-bit library availability
            // prior to 32-bit library availability.
            mNativeLibrariesLoaded =
                tryLoad( "/usr/lib64/symkey/libsymkey.so" );
            if( mNativeLibrariesLoaded ) {
                System.out.println( "64-bit symkey library loaded" );
            } else {
                // REMINDER:  May be trying to run a 32-bit app
                //            on 64-bit platform.
                mNativeLibrariesLoaded =
                    tryLoad( "/usr/lib/symkey/libsymkey.so" );
                if( mNativeLibrariesLoaded ) {
                    System.out.println( "32-bit symkey library loaded");
                } else {
                    System.out.println( "FAILED loading symkey library!");
                    System.exit( -1 );
                }
            }
        } else {
            try {
                System.loadLibrary( "symkey" );
                System.out.println( "symkey library loaded" );
                mNativeLibrariesLoaded = true;
            } catch( Throwable t ) {
                // This is bad news, the program is doomed at this point
                t.printStackTrace();
            }
        }
    }


    // external calls from RA
    public static native byte[] ComputeKeyCheck(PK11SymKey desKey ); /* byte data[] ); */

    public static native byte[] ComputeSessionKey( String tokenName,
                                                   String keyName,
                                                   byte[] card_challenge,
                                                   byte[] host_challenge,
                                                   byte[] keyInfo,
                                                   byte[] CUID,
                                                   byte[] macKeyArray,
                                                   String useSoftToken,
                                                   String keySet,
                                                   String sharedSecretKeyName );

    public static native byte[] ComputeEncSessionKey( String tokenName,
                                                      String keyName,
                                                      byte[] card_challenge,
                                                      byte[] host_challenge,
                                                      byte[] keyInfo,
                                                      byte[] CUID,
                                                      byte[] encKeyArray,
                                                      String useSoftToken,
                                                      String keySet );

    public static native PK11SymKey ComputeKekSessionKey( String tokenName,
                                                          String keyName,
                                                          byte[] card_challenge,
                                                          byte[] host_challenge,
                                                          byte[] keyInfo,
                                                          byte[] CUID,
                                                          byte[] kekKeyArray,
                                                          String useSoftToken,
                                                          String keySet );

    public static native PK11SymKey ComputeKekKey( String tokenName,
                                                   String keyName,
                                                   byte[] card_challenge,
                                                   byte[] host_challenge,
                                                   byte[] keyInfo,
                                                   byte[] CUID,
                                                   byte[] kekKeyArray,
                                                   String useSoftToken, String keySet );

    public static native byte[] ECBencrypt( PK11SymKey key,
                                            PK11SymKey desKey ); //byte[] data );

    public static native PK11SymKey GenerateSymkey( String tokenName );

    /*
     * DRM_SUPPORT_DEBUG
     */

    // public static native PK11SymKey bytes2PK11SymKey( byte[] symKeyBytes );

    public static native byte[] ComputeCryptogram( String tokenName,
                                                   String keyName,
                                                   byte[] card_challenge,
                                                   byte[] host_challenge,
                                                   byte[] keyInfo,
                                                   byte[] CUID,
                                                   int type,
                                                   byte[] authKeyArray,
                                                   String useSoftToken, String keySet );

    public static native byte[] EncryptData( String tokenName,
                                             String keyName,
                                             byte[] in,
                                             byte[] keyInfo,
                                             byte[] CUID,
                                             byte[] kekKeyArray,
                                             String useSoftToken, String keySet );

    public static native byte[] DiversifyKey( String tokenName,
                                              String newTokenName,
                                              String oldMasterKeyName,
                                              String newMasterKeyName,
                                              String keyInfo,
                                              byte[] CUIDValue,
                                              byte[] kekKeyArray,
                                              String useSoftToken, String keySet );

    // internal calls from config TKS keys tab
    public static native String GenMasterKey( String token,
                                              String keyName );

    public static native String DeleteSymmetricKey( String token,
                                                    String keyName );

    public static native String ListSymmetricKeys( String token );

    //  set when called from the config TKS tab to create master key
    //  get when called from the RA to create session key
    public static native void SetDefaultPrefix( String masterPrefix );
}

