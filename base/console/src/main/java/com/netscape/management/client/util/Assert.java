/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.util;


/**
 * Simple assertion class that throws exceptions when an assertion fails.
 */
public final class Assert {
    // Enabled flag. In theory if this is set to false the assertion
    // code can get compiled out when optimizing.
    static final boolean kEnabled = true;
    static ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    /**
     * Throw an exception if aCondition is false.
     *
     * @param aCondition  condition to assert
     */
    final public static void Assertion(boolean aCondition) {
        if (kEnabled) {
            if (!aCondition) {
                throw new AssertionError(
                        _resource.getString("assert", "Assertion"));
            }
        }
    }

    /**
      * Throw an exception always. Used when the caller runs across some
      * code that should never be reached.
      *
      * @param msg  message to display
      */
    final public static void NotReached(String msg) {
        if (kEnabled) {
            throw new AssertionError(
                    _resource.getString("assert", "NotReached") + msg);
        }
    }

    /**
      * Throw an exception always. Used when the caller runs across some
      * unimplemented functionality in pre-release code.
      *
      * @param msg  message to display
      */
    final public static void NotYetImplemented(String msg) {
        if (kEnabled) {
            throw new AssertionError(
                    _resource.getString("assert", "NoImpl") + msg);
        }
    }

    /**
      * Throw an exception if aCondition is false.
      *
      * @param aCondition  condition to assert
      */
    final public static void PreCondition(boolean aCondition) {
        if (kEnabled) {
            if (!aCondition) {
                throw new AssertionError(
                        _resource.getString("assert", "Precondition"));
            }
        }
    }

    /**
      * Throw an exception if aCondition is false.
      *
      * @param aCondition  condition to assert
      */
    final public static void PostCondition(boolean aCondition) {
        if (kEnabled) {
            if (!aCondition) {
                throw new AssertionError(
                        _resource.getString("assert", "Postcondition"));
            }
        }
    }
}
