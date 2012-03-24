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
package netscape.security.x509;

import java.security.GeneralSecurityException;

/**
 * X.509 Extension Exception.
 * 
 * @author Hemma Prafullchandra
 *         1.2
 */
public class X509ExtensionException extends GeneralSecurityException {

    /**
     *
     */
    private static final long serialVersionUID = 8152491877676477910L;

    /**
     * Constructs an X509ExtensionException with no detail message. A
     * detail message is a String that describes this particular
     * exception.
     */
    public X509ExtensionException() {
        super();
    }

    /**
     * Constructs the exception with the specified detail
     * message. A detail message is a String that describes this
     * particular exception.
     * 
     * @param message the detail message.
     */
    public X509ExtensionException(String message) {
        super(message);
    }
}
