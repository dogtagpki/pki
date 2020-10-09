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
package org.dogtagpki.legacy.core.policy;

import java.util.Vector;

import org.dogtagpki.legacy.policy.EPolicyException;
import org.dogtagpki.legacy.policy.IExpression;

import com.netscape.cmscore.apps.CMS;

/**
 * Default implementation of predicate parser.
 *
 * Limitations:
 *
 * 1. Currently parentheses are not suported.
 * 2. Only ==, != <, >, <= and >= operators are supported.
 * 3. The only boolean operators supported are AND and OR. AND takes precedence
 * over OR. Example: a AND b OR e OR c AND d
 * is treated as (a AND b) OR e OR (c AND d)
 * 4. If this is n't adequate, roll your own.
 *
 * @author kanda
 * @version $Revision$, $Date$
 */
public class PolicyPredicateParser {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PolicyPredicateParser.class);

    public static final int OP_AND = 1;
    public static final int OP_OR = 2;
    public static final int EXPRESSION = 0;

    public static final String AND = "AND";
    public static final String OR = "OR";

    private static final char COMMA = ',';

    /**
     * Parse the predicate expression and return a vector of expressions.
     *
     * @param predicateExpression The predicate expression as read from the config file.
     * @return expVector The vector of expressions.
     */
    public static IExpression parse(String predicateExpression)
            throws EPolicyException {
        if (predicateExpression == null ||
                predicateExpression.length() == 0)
            return null;
        PredicateTokenizer pt = new PredicateTokenizer(predicateExpression);

        if (pt == null || !pt.hasMoreTokens())
            return null;

        // The first token cannot be an operator. We are not dealing with
        // reverse-polish notation.
        String token = pt.nextToken();

        if (getOP(token) != EXPRESSION) {
            logger.error("Malformed expression: " + predicateExpression);
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_BAD_POLICY_EXPRESSION", predicateExpression));
        }

        IExpression current = parseExpression(token);
        boolean malformed = false;
        Vector<IExpression> expSet = new Vector<IExpression>();
        int prevType = EXPRESSION;

        while (pt.hasMoreTokens()) {
            token = pt.nextToken();
            int curType = getOP(token);

            if ((prevType != EXPRESSION && curType != EXPRESSION) ||
                    (prevType == EXPRESSION && curType == EXPRESSION)) {
                malformed = true;
                break;
            }

            // If an operator seen skip to the next token
            if (curType != EXPRESSION) {
                prevType = curType;
                continue;
            }

            // If the previous type was an OR token, add the current expression to
            // the expression set;
            if (prevType == OP_OR) {
                expSet.addElement(current);
                current = parseExpression(token);
                prevType = curType;
                continue;
            }

            // If the previous type was an AND token, make an AND expression
            if (prevType == OP_AND) {
                current = new AndExpression(current, parseExpression(token));
                prevType = curType;
            }
        }
        if (malformed) {
            logger.error("Malformed expression: " + predicateExpression);
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_BAD_POLICY_EXPRESSION",
                            predicateExpression));
        }

        // Form an ORExpression
        if (current != null)
            expSet.addElement(current);

        int size = expSet.size();

        if (size == 0)
            return null;
        OrExpression orExp = new
                OrExpression(expSet.elementAt(0), null);

        for (int i = 1; i < size; i++)
            orExp = new OrExpression(orExp,
                        expSet.elementAt(i));
        return orExp;
    }

    private static int getOP(String token) {
        if (token.equalsIgnoreCase(AND))
            return OP_AND;
        else if (token.equalsIgnoreCase(OR))
            return OP_OR;
        else
            return EXPRESSION;
    }

    private static IExpression parseExpression(String input)
            throws EPolicyException {
        // If the expression has multiple parts separated by commas
        // we need to construct an AND expression. Else we will return a
        // simple expression.
        int commaIndex = input.indexOf(COMMA);

        if (commaIndex < 0)
            return SimpleExpression.parse(input);
        int currentIndex = 0;
        Vector<SimpleExpression> expVector = new Vector<SimpleExpression>();

        while (commaIndex > 0) {
            SimpleExpression exp = (SimpleExpression)
                    SimpleExpression.parse(input.substring(currentIndex,
                            commaIndex));

            expVector.addElement(exp);
            currentIndex = commaIndex + 1;
            commaIndex = input.indexOf(COMMA, currentIndex);
        }
        if (currentIndex < (input.length() - 1)) {
            SimpleExpression exp = (SimpleExpression)
                    SimpleExpression.parse(input.substring(currentIndex));

            expVector.addElement(exp);
        }

        int size = expVector.size();
        SimpleExpression exp1 = expVector.elementAt(0);
        SimpleExpression exp2 = expVector.elementAt(1);
        AndExpression andExp = new AndExpression(exp1, exp2);

        for (int i = 2; i < size; i++) {
            andExp = new AndExpression(andExp, expVector.elementAt(i));
        }
        return andExp;
    }

    public static void main(String[] args) {

        /*********
         * IRequest req = new IRequest();
         * try
         * {
         * req.set("ou", "people");
         * req.set("cn", "John Doe");
         * req.set("uid", "jdoes");
         * req.set("o", "airius.com");
         * req.set("certtype", "client");
         * req.set("request", "issuance");
         * req.set("id", new Integer(10));
         * req.set("dualcerts", new Boolean(true));
         *
         * Vector v = new Vector();
         * v.addElement("one");
         * v.addElement("two");
         * v.addElement("three");
         * req.set("count", v);
         * }
         * catch (Exception e){e.printStackTrace();}
         * String[] array = { "ou == people AND certtype == client",
         * "ou == servergroup AND certtype == server",
         * "uid == jdoes, ou==people, o==airius.com OR ou == people AND certType == client OR certType == server AND cn == needles.mcom.com"
         * ,
         * };
         * for (int i = 0; i < array.length; i++)
         * {
         * System.out.println();
         * System.out.println("String: " + array[i]);
         * IExpression exp = null;
         * try
         * {
         * exp = parse(array[i]);
         * if (exp != null)
         * {
         * System.out.println("Parsed Expression: " + exp);
         * boolean result = exp.evaluate(req);
         * System.out.println("Result: " + result);
         * }
         * }
         * catch (Exception e) {e.printStackTrace(); }
         * }
         *
         *
         * try
         * {
         * BufferedReader rdr = new BufferedReader(
         * new FileReader(args[0]));
         * String line;
         * while((line=rdr.readLine()) != null)
         * {
         * System.out.println();
         * System.out.println("Line Read: " + line);
         * IExpression exp = null;
         * try
         * {
         * exp = parse(line);
         * if (exp != null)
         * {
         * System.out.println(exp);
         * boolean result = exp.evaluate(req);
         * System.out.println("Result: " + result);
         * }
         *
         * }catch (Exception e){e.printStackTrace();}
         * }
         * }
         * catch (Exception e){e.printStackTrace(); }
         *******/
    }

}
