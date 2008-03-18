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


import java.io.*;
import java.util.*;
import org.mozilla.jss.pkcs11.*;


/**
 * This object contains the OS independent interfaces. 
 */
public class SessionKey
{
    static
    {
        try {
            System.loadLibrary( "symkey" );
        } catch( Throwable t ) {
            // This is bad news, the program is doomed at this point
            t.printStackTrace();
        }
    }

    // external calls from RA
    public static native byte[] ComputeKeyCheck( byte data[] );

    public static native byte[] ComputeCardCryptogram( byte[] raw_auth_key,
                                                       byte[] card_challenge,
                                                       byte[] host_challenge );

    public static native byte[] ComputeSessionKey( String tokenName,
                                                   String keyName,
                                                   byte[] card_challenge,
                                                   byte[] host_challenge,
                                                   byte[] keyInfo,
                                                   byte[] CUID,
                                                   byte[] macKeyArray,
                                                   String useSoftToken );

    public static native byte[] ComputeEncSessionKey( String tokenName,
                                                      String keyName,
                                                      byte[] card_challenge,
                                                      byte[] host_challenge,
                                                      byte[] keyInfo,
                                                      byte[] CUID,
                                                      byte[] encKeyArray,
                                                      String useSoftToken );

    public static native PK11SymKey ComputeKekSessionKey( String tokenName,
                                                          String keyName,
                                                          byte[] card_challenge,
                                                          byte[] host_challenge,
                                                          byte[] keyInfo,
                                                          byte[] CUID,
                                                          byte[] kekKeyArray,
                                                          String useSoftToken );

    public static native PK11SymKey ComputeKekKey( String tokenName,
                                                   String keyName,
                                                   byte[] card_challenge,
                                                   byte[] host_challenge,
                                                   byte[] keyInfo,
                                                   byte[] CUID,
                                                   byte[] kekKeyArray,
                                                   String useSoftToken );

    public static native byte[] ECBencrypt( PK11SymKey key,
                                            byte[] data );

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
                                                   String useSoftToken );

    public static native byte[] EncryptData( String tokenName,
                                             String keyName,
                                             byte[] in,
                                             byte[] keyInfo,
                                             byte[] CUID,
                                             byte[] kekKeyArray,
                                             String useSoftToken );

    public static native byte[] DiversifyKey( String tokenName,
                                              String newTokenName,
                                              String oldMasterKeyName,
                                              String newMasterKeyName,
                                              String keyInfo,
                                              byte[] CUIDValue,
                                              byte[] kekKeyArray,
                                              String useSoftToken );

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

