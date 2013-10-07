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
package com.netscape.cmscore.policy;

import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IExpression;
import com.netscape.certsrv.request.IRequest;

/**
 * This class represents an Or expression of the form
 * (var1 op val1 OR var2 op val2).
 *
 * Expressions are used as predicates for policy selection.
 *
 * @deprecated
 * @author kanda
 * @version $Revision$, $Date$
 */
public class OrExpression implements IExpression {
    private IExpression mExp1;
    private IExpression mExp2;

    public OrExpression(IExpression exp1, IExpression exp2) {
        mExp1 = exp1;
        mExp2 = exp2;
    }

    public boolean evaluate(IRequest req)
            throws EPolicyException {
        if (mExp1 == null && mExp2 == null)
            return true;
        else if (mExp1 != null && mExp2 != null)
            return mExp1.evaluate(req) || mExp2.evaluate(req);
        else if (mExp1 != null && mExp2 == null)
            return mExp1.evaluate(req);
        else
            // (mExp1 == null && mExp2 != null)
            return mExp2.evaluate(req);
    }

    public String toString() {
        if (mExp1 == null && mExp2 == null)
            return "";
        else if (mExp1 != null && mExp2 != null)
            return mExp1.toString() + " OR " + mExp2.toString();
        else if (mExp1 != null && mExp2 == null)
            return mExp1.toString();
        else
            // (mExp1 == null && mExp2 != null)
            return mExp2.toString();
    }
}
