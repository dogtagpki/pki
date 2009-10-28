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


/**
 * This class is a simple reflection of the Unix getuid/setuid
 * functionality
 */
public class UserID {

    /**
     * Return the current real user ID of the JavaVM
     */
    public static native int get();

    /**
     * Return the current effective user ID of the JavaVM
     */
    public static native int getEffective();

    /**
     * Set the current real user ID of the JavaVM
     *
     * @param id the user id
     */
    public static native void set(int id);

    /**
     * Set the current real user ID of the JavaVM
     *
     * @param user the user name
     */
    public static native void set(String user);

    /**
     * Set the current effective user ID of the JavaVM
     *
     * @param id the user id
     */
    public static native void setEffective(int id);

    /**
     * Set the current effective user ID of the JavaVM
     *
     * @param user the user name
     */
    public static native void setEffective(String user);

    static {
        boolean mNativeLibrariesLoaded = false;
        if (File.separatorChar == '/') {
            String os = System.getProperty( "os.name" );
            if( ( os.equals( "Linux" ) ) ||
                ( os.equals( "Solaris" ) ) ) {
                // Check for 64-bit library availability
                // prior to 32-bit library availability.
                mNativeLibrariesLoaded =
                    OSUtil.tryLoad( "/usr/lib64/osutil/libosutil.so" );
                if( mNativeLibrariesLoaded ) {
                    System.out.println( "64-bit osutil library loaded" );
                } else {
                    // REMINDER:  May be trying to run a 32-bit app
                    //            on 64-bit platform.
                    mNativeLibrariesLoaded =
                        OSUtil.tryLoad( "/usr/lib/osutil/libosutil.so" );
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
    }
}

