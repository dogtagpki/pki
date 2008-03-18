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

    // Load native library
    static {
        System.loadLibrary( "osutil" );
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

