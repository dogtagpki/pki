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
package com.netscape.certsrv.publish;


import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.request.IRequest;


/**
 * Interface for a Ldap predicate expression.
 *
 * @version $Revision$, $Date$
 */
public interface ILdapExpression {
    public static final int OP_EQUAL = 1;
    public static final int OP_NEQUAL = 2;
    public static final int OP_GT = 3;
    public static final int OP_LT = 4;
    public static final int OP_GE = 5;
    public static final int OP_LE = 6;
    public static final String EQUAL_STR = "==";
    public static final String NEQUAL_STR = "!=";
    public static final String GT_STR = ">";
    public static final String GE_STR = ">=";
    public static final String LT_STR = "<";
    public static final String LE_STR = "<=";

    /**
     * Evaluate the Expression.
     *
     * @param   sc       The SessionContext on which we are applying the condition.
     * @return          The return value.
     * @exception          ELdapExeption  Failed to evaluate expression.
     */
    boolean evaluate(SessionContext sc)
        throws ELdapException;

    /**
     * Evaluate the Expression.
     *
     * @param    req	The PKIRequest on which we are applying the condition.
     * @return 		The return value.
     * @exception          ELdapExeption  Failed to evaluate expression.
     */
    boolean evaluate(IRequest req)
        throws ELdapException;

    /**
     * Convert to a string.
     * @return String representation of expression.
     */
    public String toString();
}

