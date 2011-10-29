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

import java.util.Vector;
import java.util.Enumeration;

/**
 * <p>This class provides the Enumeration implementation used
 * by all the X509 certificate attributes to return the attribute
 * names contained within them.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.3
 */
public class AttributeNameEnumeration extends Vector {
    /**
     * The default constructor for this class.
     */
    public AttributeNameEnumeration() {
        super(1,1);
    }
}
