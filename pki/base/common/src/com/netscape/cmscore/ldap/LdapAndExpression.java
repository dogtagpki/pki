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
package com.netscape.cmscore.ldap;


import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;


/**
 * This class represents an expression of the form
 * <var1 op val1 AND var2 op va2>.
 *
 * Expressions are used as predicates for publishing rule selection.
 *
 * @author mzhao
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class LdapAndExpression implements ILdapExpression {
    private ILdapExpression mExp1;
    private ILdapExpression mExp2;
    public LdapAndExpression(ILdapExpression exp1, ILdapExpression exp2) {
        mExp1 = exp1;
        mExp2 = exp2;
    }

    public boolean evaluate(SessionContext sc)
        throws ELdapException {
        // If an expression is missing we assume applicability.
        if (mExp1 == null && mExp2 == null)
            return true;
        else if (mExp1 != null && mExp2 != null)
            return mExp1.evaluate(sc) && mExp2.evaluate(sc);
        else if (mExp1 == null)
            return mExp2.evaluate(sc);
        else // (if mExp2 == null)
            return mExp1.evaluate(sc);
    }

    public boolean evaluate(IRequest req)
        throws ELdapException {
        // If an expression is missing we assume applicability.
        if (mExp1 == null && mExp2 == null)
            return true;
        else if (mExp1 != null && mExp2 != null)
            return mExp1.evaluate(req) && mExp2.evaluate(req);
        else if (mExp1 == null)
            return mExp2.evaluate(req);
        else // (if mExp2 == null)
            return mExp1.evaluate(req);
    }

    public String toString() {
        return mExp1.toString() + " AND " + mExp2.toString();
    }
}

