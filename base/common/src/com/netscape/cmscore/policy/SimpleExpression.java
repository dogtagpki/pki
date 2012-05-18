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

import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IExpression;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.util.AssertionException;
import com.netscape.cmscore.util.Debug;

/**
 * This class represents an expression of the form var = val,
 * var != val, var < val, var > val, var <= val, var >= val.
 *
 * Expressions are used as predicates for policy selection.
 *
 * @deprecated
 * @author kanda
 * @version $Revision$, $Date$
 */
public class SimpleExpression implements IExpression {
    private String mPfx;
    private String mVar;
    private String mVal;
    private String mPartialMatch;
    private int mOp;
    private boolean hasWildCard;
    public static final char WILDCARD_CHAR = '*';

    // This is just for indicating a null expression.
    public static SimpleExpression NULL_EXPRESSION = new SimpleExpression("null", OP_EQUAL, "null");

    public static IExpression parse(String input)
            throws EPolicyException {
        // Get the index of operator
        // Debug.trace("SimpleExpression::input: " + input);
        String var = null;
        int op = -1;
        String val = null;

        // XXX - Kanda - Need to change this parsing code eventually.
        ExpressionComps comps = parseForEquality(input);

        if (comps == null)
            comps = parseForInEquality(input);
        if (comps == null)
            comps = parseForGE(input);
        if (comps == null)
            comps = parseForLE(input);
        if (comps == null)
            comps = parseForGT(input);
        if (comps == null)
            comps = parseForLT(input);
        if (comps == null)
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_BAD_POLICY_EXPRESSION", input));
        String pfx = null;
        String rawVar = comps.getAttr();
        int dotIdx = rawVar.indexOf('.');

        if (dotIdx != -1) {
            pfx = rawVar.substring(0, dotIdx).trim();
            var = rawVar.substring(dotIdx + 1).trim();
        } else {
            var = rawVar;
        }
        op = comps.getOp();
        val = comps.getVal();
        return new SimpleExpression(pfx, var, op, val);
    }

    public SimpleExpression(String var, int op, String val) {
        this(null, var, op, val);
    }

    public SimpleExpression(String prefix, String var, int op, String val) {
        // Assert that op has to be either IExpression.OP_EQUAL or
        // IExpression.OP_NEQUAL.
        // If val or var is null throw an exception!
        mPfx = prefix;
        mVar = var;
        mOp = op;
        mVal = val;
        int firstIndex;

        if ((firstIndex = mVal.indexOf(WILDCARD_CHAR)) >= 0) {
            hasWildCard = true;
            int nextIndex = mVal.indexOf(WILDCARD_CHAR, firstIndex + 1);

            if (nextIndex == -1) {
                if (firstIndex == 0)
                    mPartialMatch = mVal.substring(1);
                else
                    mPartialMatch = mVal.substring(0, firstIndex);
            } else
                mPartialMatch = mVal.substring(firstIndex + 1, nextIndex);
        } else
            hasWildCard = false;
    }

    public boolean evaluate(IRequest req)
            throws EPolicyException {
        // mPfx and mVar are looked up case-indendently
        String givenVal = req.getExtDataInString(mPfx, mVar);

        if (Debug.ON)
            Debug.trace("mPfx: " + mPfx + " mVar: " + mVar +
                    ",Given Value: " + givenVal + ", Value to compare with: " + mVal);

        return matchValue(givenVal);
    }

    private boolean matchVector(Vector<?> value)
            throws EPolicyException {
        boolean result = false;
        Enumeration<?> e = value.elements();

        for (; e.hasMoreElements();) {
            result = matchValue(e.nextElement());
            if (result)
                break;
        }
        return result;
    }

    private boolean matchStringArray(String[] value)
            throws EPolicyException {
        boolean result = false;

        for (int i = 0; i < value.length; i++) {
            result = matchValue(value[i]);
            if (result)
                break;
        }
        return result;
    }

    private boolean matchValue(Object value)
            throws EPolicyException {
        boolean result;

        // There is nothing to compare with!
        if (value == null)
            return false;

        // XXX - Kanda: We need a better way of handling this!.
        if (value instanceof String)
            result = matchStringValue((String) value);
        else if (value instanceof Integer)
            result = matchIntegerValue((Integer) value);
        else if (value instanceof Boolean)
            result = matchBooleanValue((Boolean) value);
        else if (value instanceof Vector)
            result = matchVector((Vector<?>) value);
        else if (value instanceof String[])
            result = matchStringArray((String[]) value);
        else
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_INVALID_ATTR_VALUE",
                        value.getClass().getName()));
        return result;
    }

    private boolean matchStringValue(String givenVal)
            throws EPolicyException {
        boolean result;

        switch (mOp) {
        case OP_EQUAL:
            if (hasWildCard)
                result = (givenVal.indexOf(mPartialMatch) >= 0);
            else
                result = givenVal.equalsIgnoreCase(mVal);
            break;

        case OP_NEQUAL:
            if (hasWildCard)
                result = (givenVal.indexOf(mPartialMatch) < 0);
            else
                result = !givenVal.equalsIgnoreCase(mVal);
            break;

        case OP_LT:
            result = (givenVal.compareTo(mVal) < 0);
            break;

        case OP_GT:
            result = (givenVal.compareTo(mVal) > 0);
            break;

        case OP_GE:
            result = (givenVal.compareTo(mVal) >= 0);
            break;

        case OP_LE:
            result = (givenVal.compareTo(mVal) >= 0);
            break;

        default:
            throw new AssertionException("Invalid operation code");
        }
        return result;
    }

    private boolean matchIntegerValue(Integer intVal)
            throws EPolicyException {
        boolean result;
        int storedVal;
        int givenVal = intVal.intValue();

        try {
            storedVal = new Integer(mVal).intValue();
        } catch (Exception e) {
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_INVALID_ATTR_VALUE", mVal));

        }
        switch (mOp) {
        case OP_EQUAL:
            result = (givenVal == storedVal);
            break;

        case OP_NEQUAL:
            result = (givenVal != storedVal);
            break;

        case OP_LT:
            result = (givenVal < storedVal);
            break;

        case OP_GT:
            result = (givenVal > storedVal);
            break;

        case OP_GE:
            result = (givenVal >= storedVal);
            break;

        case OP_LE:
            result = (givenVal >= storedVal);
            break;

        default:
            throw new AssertionException("Invalid operation code");
        }
        return result;
    }

    private boolean matchBooleanValue(Boolean givenVal)
            throws EPolicyException {
        boolean result;
        Boolean storedVal;

        if (!(mVal.equalsIgnoreCase("true") || mVal.equalsIgnoreCase("false")))
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_INVALID_ATTR_VALUE",
                        mVal));
        storedVal = Boolean.valueOf(mVal);
        switch (mOp) {
        case OP_EQUAL:
            result = (givenVal.equals(storedVal));
            break;

        case OP_NEQUAL:
        case OP_LT:
        case OP_GT:
        case OP_GE:
        case OP_LE:
            result = (!givenVal.equals(storedVal));
            break;

        default:
            throw new AssertionException("Invalid operation code");
        }
        return result;
    }

    public String toString() {
        String op = null;

        switch (mOp) {
        case IExpression.OP_EQUAL:
            op = IExpression.EQUAL_STR;
            break;

        case IExpression.OP_NEQUAL:
            op = IExpression.NEQUAL_STR;
            break;

        case IExpression.OP_GT:
            op = IExpression.GT_STR;
            break;

        case IExpression.OP_LT:
            op = IExpression.LT_STR;
            break;

        case IExpression.OP_GE:
            op = IExpression.GE_STR;
            break;

        case IExpression.OP_LE:
            op = IExpression.LE_STR;
            break;
        }
        if (mPfx != null && mPfx.length() > 0)
            return mPfx + "." + mVar + " " + op + " " + mVal;
        else
            return mVar + " " + op + " " + mVal;
    }

    private static ExpressionComps parseForEquality(String expression) {
        int index = expression.indexOf(IExpression.EQUAL_STR);

        if (index < 0)
            return null;
        else {
            String attr = expression.substring(0, index).trim();
            int op = OP_EQUAL;
            String val = expression.substring(index + 2).trim();

            return new ExpressionComps(attr, op, val);
        }
    }

    private static ExpressionComps parseForInEquality(String expression) {
        int index = expression.indexOf(IExpression.NEQUAL_STR);

        if (index < 0)
            return null;
        else {
            String attr = expression.substring(0, index).trim();
            int op = OP_NEQUAL;
            String val = expression.substring(index + 2).trim();

            return new ExpressionComps(attr, op, val);
        }
    }

    private static ExpressionComps parseForGT(String expression) {
        int index = expression.indexOf(IExpression.GT_STR);

        if (index < 0)
            return null;
        else {
            String attr = expression.substring(0, index).trim();
            int op = OP_GT;
            String val = expression.substring(index + 1).trim();

            return new ExpressionComps(attr, op, val);
        }
    }

    private static ExpressionComps parseForLT(String expression) {
        int index = expression.indexOf(IExpression.LT_STR);

        if (index < 0)
            return null;
        else {
            String attr = expression.substring(0, index).trim();
            int op = OP_LT;
            String val = expression.substring(index + 1).trim();

            return new ExpressionComps(attr, op, val);
        }
    }

    private static ExpressionComps parseForGE(String expression) {
        int index = expression.indexOf(IExpression.GE_STR);

        if (index < 0)
            return null;
        else {
            String attr = expression.substring(0, index).trim();
            int op = OP_GE;
            String val = expression.substring(index + 2).trim();

            return new ExpressionComps(attr, op, val);
        }
    }

    private static ExpressionComps parseForLE(String expression) {
        int index = expression.indexOf(IExpression.LE_STR);

        if (index < 0)
            return null;
        else {
            String attr = expression.substring(0, index).trim();
            int op = OP_LE;
            String val = expression.substring(index + 2).trim();

            return new ExpressionComps(attr, op, val);
        }
    }
}

class ExpressionComps {
    String attr;
    int op;
    String val;

    public ExpressionComps(String a, int o, String v) {
        attr = a;
        op = o;
        val = v;
    }

    public String getAttr() {
        return attr;
    }

    public int getOp() {
        return op;
    }

    public String getVal() {
        return val;
    }
}
