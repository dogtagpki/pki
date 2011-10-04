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
 * This class is to enabled reading/setting of various resource limits
 * on unix
 */
public class ResourceLimit {

    /**
     * Return the current process id of the Java VM
     */

    /**
     * See /usr/include/sys/resource.h
     */
    public static int RLIMIT_CPU = 0;
    public static int RLIMIT_FSIZE = 1;
    public static int RLIMIT_DATA = 2;
    public static int RLIMIT_STACK = 3;
    public static int RLIMIT_CORE = 4;
    public static int RLIMIT_NOFILE = 5;
    public static int RLIMIT_VMEM = 6;

    /**
     * Return the hard limit of the specified resource 
     */
    public static native int getHardLimit(int resource);

    /**
     * Return the soft limit of the specified resource 
     */
    public static native int getSoftLimit(int resource);

    /**
     * Set limits on the resource
     */
    public static native int setLimits(int resource, int soft, int hard);

    static {
        boolean mNativeLibrariesLoaded = false;
        if (File.separatorChar == '/') {
            String os = System.getProperty( "os.name" );
            if( ( os.equals( "Linux" ) ) ) {
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

    /* little test program here... */

    public static void main(String args[]) {
        try {
            testFDlimit("64");
            printFDLimit();
            System.gc();
            System.out.println("Changing softlimit to be equal to hardlimit()");

            setLimits(RLIMIT_NOFILE, 
                getHardLimit(RLIMIT_NOFILE),
                getHardLimit(RLIMIT_NOFILE)
            );

            testFDlimit("1024");
            printFDLimit();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static void printFDLimit() {
        System.out.println("Max filedescs (hardlimit) " + getHardLimit(RLIMIT_NOFILE));
        System.out.println("Max filedescs (softlimit) " + getSoftLimit(RLIMIT_NOFILE));
    }

    /* this creates as many files as it can. The files will be closed when this
     function exits, as they will be garbage collected. */

    private static void testFDlimit(String a) {
        int count = 0;
        FileOutputStream f[] = new FileOutputStream[1024];

        try {
            for (count = 0; count < 1024; count++) {
                f[count] = new FileOutputStream("test_" + a + "_" + count);
            }
        } catch (Exception e) {
        }
    }

}

