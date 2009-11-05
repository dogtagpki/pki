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
package com.netscape.osutil;

import java.io.*;
import java.util.*;


public final class OSUtil {
    /**
     * Causes this process to die.  Works more reliably than System.exit().
     */
    public static native void nativeExit( int status );

    public static native String BtoA( byte data[] );

    public static native byte[] AtoB( String data );

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
                tryLoad( "/usr/lib64/osutil/libosutil.so" );
            if( mNativeLibrariesLoaded ) {
                System.out.println( "64-bit osutil library loaded" );
            } else {
                // REMINDER:  May be trying to run a 32-bit app
                //            on 64-bit platform.
                mNativeLibrariesLoaded =
                    tryLoad( "/usr/lib/osutil/libosutil.so" );
                if( mNativeLibrariesLoaded ) {
                    System.out.println( "32-bit osutil library loaded");
                } else {
                    System.out.println( "FAILED loading osutil library!");
                    System.exit( -1 );
                }
            }
        } else {
            try {
                System.loadLibrary( "osutil" );
                System.out.println( "osutil library loaded" );
                mNativeLibrariesLoaded = true;
            } catch( Throwable t ) {
                // This is bad news, the program is doomed at this point
                t.printStackTrace();
            }
        }
    }

    public static native int getNTpid();

    /** 
     * A routine to get the value of an system or environment variable.
     * @param envName A string of the form <code> env_var=value </code>
     * @return String value of the environemnt variable. 
     */
    public static native String getenv( String envName );

    /** 
     * A routine to set an environment variable.
     * @param envName A string of the form <code> env_var=value </code>
     * @return Return 0 on success, non-zero on failure
     */
    public static native int putenv( String envValue );

    /**
     * A routine to get a file system read lock.
     * @param filename A file with relative or absolute path
     * @return Return 0 on getting a unique read lock,
     *         Return 1 on getting non-unique read lock, -1 on failure
     */
    public static native int getFileReadLock( String filename );

    /** 
     * A routine to get a file system write lock.
     * @param filename A file with relative or absolute path
     * @return Return 0 on successfully getting a write lock,
     *         return 1 if the file is read locked,
     *         return 2 if the file is write locked, -1 on failure
     */
    public static native int getFileWriteLock( String filename );
}

