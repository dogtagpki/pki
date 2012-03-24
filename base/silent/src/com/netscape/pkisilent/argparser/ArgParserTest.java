package com.netscape.pkisilent.argparser;

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

/**
 * Copyright John E. Lloyd, 2004. All rights reserved. Permission to use,
 * copy, modify and redistribute is granted, provided that this copyright
 * notice is retained and the author is given credit whenever appropriate.
 *
 * This  software is distributed "as is", without any warranty, including 
 * any implied warranty of merchantability or fitness for a particular
 * use. The author assumes no responsibility for, and shall not be liable
 * for, any special, indirect, or consequential damages, or any damages
 * whatsoever, arising out of or in connection with the use of this
 * software.
 */

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.util.Vector;

/**
 * Testing class for the class ArgParser. Executing the <code>main</code> method of this class will perform a suite of
 * tests to help verify correct
 * operation of the parser class.
 * 
 * @author John E. Lloyd, Fall 2004
 * @see ArgParser
 */
public class ArgParserTest {
    ArgParser parser;

    static final boolean CLOSED = true;
    static final boolean OPEN = false;

    static final boolean ONE_WORD = true;
    static final boolean MULTI_WORD = false;

    private static void verify(boolean ok, String msg) {
        if (!ok) {
            Throwable e = new Throwable();
            System.out.println("Verification failed:" + msg);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static String[] argsFromString(String s) {
        Vector<String> vec = new Vector<String>(100);
        try {
            ArgParser.stringToArgs(vec, s, /*allowQuotedStings=*/false);
        } catch (StringScanException e) {
            e.printStackTrace();
            System.exit(1);
        }
        String[] result = new String[vec.size()];
        for (int i = 0; i < vec.size(); i++) {
            result[i] = (String) vec.get(i);
        }
        return result;
    }

    static class RngCheck {
        ArgParser.RangePnt low = null;
        ArgParser.RangePnt high = null;
        int type;

        RngCheck(String s) {
            low = new ArgParser.RangePnt(s, CLOSED);
            type = 's';
        }

        RngCheck(double d) {
            low = new ArgParser.RangePnt(d, CLOSED);
            type = 'd';
        }

        RngCheck(long l) {
            low = new ArgParser.RangePnt(l, CLOSED);
            type = 'l';
        }

        RngCheck(boolean b) {
            low = new ArgParser.RangePnt(b, CLOSED);
            type = 'b';
        }

        RngCheck(String s1, boolean c1, String s2, boolean c2) {
            low = new ArgParser.RangePnt(s1, c1);
            high = new ArgParser.RangePnt(s2, c2);
            type = 's';
        }

        RngCheck(double d1, boolean c1, double d2, boolean c2) {
            low = new ArgParser.RangePnt(d1, c1);
            high = new ArgParser.RangePnt(d2, c2);
            type = 'd';
        }

        RngCheck(long l1, boolean c1, long l2, boolean c2) {
            low = new ArgParser.RangePnt(l1, c1);
            high = new ArgParser.RangePnt(l2, c2);
            type = 'l';
        }

        void check(ArgParser.RangeAtom ra) {
            verify((ra.low == null) == (low == null),
                    "(ra.low==null)=" + (ra.low == null) +
                            "(low==null)=" + (low == null));
            verify((ra.high == null) == (high == null),
                    "(ra.high==null)=" + (ra.high == null) +
                            "(high==null)=" + (high == null));

            if (ra.low != null) {
                switch (type) {
                case 'l': {
                    verify(ra.low.lval == low.lval,
                            "ra.low=" + ra.low + " low=" + low);
                    break;
                }
                case 'd': {
                    verify(ra.low.dval == low.dval,
                            "ra.low=" + ra.low + " low=" + low);
                    break;
                }
                case 's': {
                    verify(ra.low.sval.equals(low.sval),
                            "ra.low=" + ra.low + " low=" + low);
                    break;
                }
                case 'b': {
                    verify(ra.low.bval == low.bval,
                            "ra.low=" + ra.low + " low=" + low);
                    break;
                }
                }
                verify(ra.low.closed == low.closed,
                        "ra.low=" + ra.low + " low=" + low);
            }
            if (ra.high != null) {
                switch (type) {
                case 'l': {
                    verify(ra.high.lval == high.lval,
                            "ra.high=" + ra.high + " high=" + high);
                    break;
                }
                case 'd': {
                    verify(ra.high.dval == high.dval,
                            "ra.high=" + ra.high + " high=" + high);
                    break;
                }
                case 's': {
                    verify(ra.high.sval.equals(high.sval),
                            "ra.high=" + ra.high + " high=" + high);
                    break;
                }
                case 'b': {
                    verify(ra.high.bval == high.bval,
                            "ra.high=" + ra.high + " high=" + high);
                    break;
                }
                }
                verify(ra.high.closed == high.closed,
                        "ra.high=" + ra.high + " high=" + high);
            }
        }
    }

    ArgParserTest() {
        parser = new ArgParser("fubar");
    }

    static void checkException(Exception e, String errmsg) {
        if (errmsg != null) {
            if (!e.getMessage().equals(errmsg)) {
                System.out.println(
                        "Expecting exception '" + errmsg + "' but got '" +
                                e.getMessage() + "'");
                e.printStackTrace();
                (new Throwable()).printStackTrace();
                System.exit(1);
            }
        } else {
            System.out.println(
                    "Unexpected exception '" + e.getMessage() + "'");
            e.printStackTrace();
            (new Throwable()).printStackTrace();
            System.exit(1);
        }
    }

    void checkPrintHelp(String msg) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(0x10000);
        PrintStream ps = new PrintStream(buf);
        ps.println(parser.getHelpMessage());
        System.out.print(buf.toString());
    }

    // 	void checkGetSynopsis (String msg)
    // 	 {
    // 	   ByteArrayOutputStream buf = new ByteArrayOutputStream(0x10000);
    // 	   PrintStream ps = new PrintStream(buf);
    // 	   parser.printSynopsis (ps, 80);
    // 	   System.out.print (buf.toString());	   
    // 	 }

    void checkAdd(String s, Object resHolder, String errmsg) {
        checkAdd(s, resHolder, 0, 0, null, null, null, errmsg);
    }

    void add(String s, Object resHolder) {
        try {
            parser.addOption(s, resHolder);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    void checkStringArray(String msg, String[] strs, String[] check) {
        boolean dontMatch = false;
        if (strs.length != check.length) {
            dontMatch = true;
        } else {
            for (int i = 0; i < strs.length; i++) {
                if (!strs[i].equals(check[i])) {
                    dontMatch = true;
                    break;
                }
            }
        }
        if (dontMatch) {
            System.out.println(msg);
            System.out.print("Expected: ");
            for (int i = 0; i < check.length; i++) {
                System.out.print("'" + check[i] + "'");
                if (i < check.length - 1) {
                    System.out.print(" ");
                }
            }
            System.out.println("");
            System.out.print("Got: ");
            for (int i = 0; i < strs.length; i++) {
                System.out.print("'" + strs[i] + "'");
                if (i < strs.length - 1) {
                    System.out.print(" ");
                }
            }
            System.out.println("");
            System.exit(1);
        }
    }

    void checkAdd(String s, Object resHolder, int code, int numValues,
               Object names, RngCheck[] rngCheck,
               String helpMsg, String errmsg) {
        boolean exceptionThrown = false;
        String[] namelist = null;
        try {
            parser.addOption(s, resHolder);
        } catch (Exception e) {
            exceptionThrown = true;
            checkException(e, errmsg);
        }
        if (names instanceof String) {
            namelist = new String[] { (String) names };
        } else {
            namelist = (String[]) names;
        }
        if (!exceptionThrown) {
            verify(errmsg == null,
                    "Expecting exception " + errmsg);
            ArgParser.Record rec = parser.lastMatchRecord();
            verify(rec.convertCode == code,
                    "code=" + rec.convertCode + ", expecting " + code);
            ArgParser.NameDesc nd;
            int i = 0;
            for (nd = rec.firstNameDesc(); nd != null; nd = nd.next) {
                i++;
            }
            verify(i == namelist.length,
                    "numNames=" + i + ", expecting " + namelist.length);
            i = 0;
            for (nd = rec.firstNameDesc(); nd != null; nd = nd.next) {
                String ss;
                if (!nd.oneWord) {
                    ss = new String(nd.name) + ' ';
                } else {
                    ss = nd.name;
                }
                verify(ss.equals(namelist[i]),
                        "have name '" + ss + "', expecting '" + namelist[i] + "'");
                i++;
            }
            ArgParser.RangeAtom ra;
            i = 0;
            for (ra = rec.firstRangeAtom(); ra != null; ra = ra.next) {
                i++;
            }
            int expectedRangeNum = 0;
            if (rngCheck != null) {
                expectedRangeNum = rngCheck.length;
            }
            verify(i == expectedRangeNum,
                    "numRangeAtoms=" + i + ", expecting " + expectedRangeNum);
            i = 0;
            for (ra = rec.firstRangeAtom(); ra != null; ra = ra.next) {
                rngCheck[i++].check(ra);
            }
            verify(rec.helpMsg.equals(helpMsg),
                    "helpMsg=" + rec.helpMsg + ", expecting " + helpMsg);
            verify(rec.numValues == numValues,
                    "numValues=" + rec.numValues + ", expecting " + numValues);
        }
    }

    double getDoubleValue(Object obj, int k) {
        if (obj instanceof DoubleHolder) {
            return ((DoubleHolder) obj).value;
        } else if (obj instanceof FloatHolder) {
            return ((FloatHolder) obj).value;
        } else if (obj instanceof double[]) {
            return ((double[]) obj)[k];
        } else if (obj instanceof float[]) {
            return ((float[]) obj)[k];
        } else {
            verify(false, "object doesn't contain double values");
            return 0;
        }
    }

    long getLongValue(Object obj, int k) {
        if (obj instanceof LongHolder) {
            return ((LongHolder) obj).value;
        } else if (obj instanceof IntHolder) {
            return ((IntHolder) obj).value;
        } else if (obj instanceof long[]) {
            return ((long[]) obj)[k];
        } else if (obj instanceof int[]) {
            return ((int[]) obj)[k];
        } else {
            verify(false, "object doesn't contain long values");
            return 0;
        }
    }

    String getStringValue(Object obj, int k) {
        if (obj instanceof StringHolder) {
            return ((StringHolder) obj).value;
        } else if (obj instanceof String[]) {
            return ((String[]) obj)[k];
        } else {
            verify(false, "object doesn't contain String values");
            return null;
        }
    }

    boolean getBooleanValue(Object obj, int k) {
        if (obj instanceof BooleanHolder) {
            return ((BooleanHolder) obj).value;
        } else if (obj instanceof boolean[]) {
            return ((boolean[]) obj)[k];
        } else {
            verify(false, "object doesn't contain boolean values");
            return false;
        }
    }

    char getCharValue(Object obj, int k) {
        if (obj instanceof CharHolder) {
            return ((CharHolder) obj).value;
        } else if (obj instanceof char[]) {
            return ((char[]) obj)[k];
        } else {
            verify(false, "object doesn't contain char values");
            return 0;
        }
    }

    static class MErr {
        int code;
        String valStr;

        MErr(int code, String valStr) {
            this.code = code;
            this.valStr = valStr;
        }
    }

    static class MTest {
        String args;
        Object result;
        int resultIdx;

        MTest(String args, Object result) {
            this(args, result, -1);
        }

        MTest(String args, Object result, int resultIdx) {
            this.args = args;
            this.result = result;
            this.resultIdx = resultIdx;
        }
    };

    void checkMatch(String args[], int idx, String errMsg) {
        getMatchResult(args, idx, -1, errMsg, -1);
    }

    void checkMatch(String args[], int idx, int cnt,
             long check, int resultIdx) {
        Object rholder = getMatchResult(args, idx, cnt, null, resultIdx);
        long result = getLongValue(rholder, 0);
        verify(result == check, "result " + result + " vs. " + check);
    }

    void checkMatch(String args[], int idx, int cnt,
             double check, int resultIdx) {
        Object rholder = getMatchResult(args, idx, cnt, null, resultIdx);
        double result = getDoubleValue(rholder, 0);
        verify(result == check, "result " + result + " vs. " + check);
    }

    void checkMatch(String args[], int idx, int cnt,
             String check, int resultIdx) {
        Object rholder = getMatchResult(args, idx, cnt, null, resultIdx);
        String result = getStringValue(rholder, 0);
        verify(result.equals(check), "result " + result + " vs. " + check);
    }

    void checkMatch(String args[], int idx, int cnt,
             boolean check, int resultIdx) {
        Object rholder = getMatchResult(args, idx, cnt, null, resultIdx);
        boolean result = getBooleanValue(rholder, 0);
        verify(result == check, "result " + result + " vs. " + check);
    }

    void checkMatch(String args[], int idx, int cnt,
             char check, int resultIdx) {
        Object rholder = getMatchResult(args, idx, cnt, null, resultIdx);
        char result = getCharValue(rholder, 0);
        verify(result == check, "result " + result + " vs. " + check);
    }

    void checkMatch(String args[], int idx, int cnt,
             Object checkArray, int resultIdx) {
        Object rholder = getMatchResult(args, idx, cnt, null, resultIdx);
        if (!checkArray.getClass().isArray()) {
            verify(false, "check is not an array");
        }
        for (int i = 0; i < Array.getLength(checkArray); i++) {
            if (checkArray instanceof long[]) {
                long result = getLongValue(rholder, i);
                long check = ((long[]) checkArray)[i];
                verify(result == check,
                        "result [" + i + "] " + result + " vs. " + check);
            } else if (checkArray instanceof double[]) {
                double result = getDoubleValue(rholder, i);
                double check = ((double[]) checkArray)[i];
                verify(result == check,
                        "result [" + i + "] " + result + " vs. " + check);
            } else if (checkArray instanceof String[]) {
                String result = getStringValue(rholder, i);
                String check = ((String[]) checkArray)[i];
                verify(result.equals(check),
                        "result [" + i + "] " + result + " vs. " + check);
            } else if (checkArray instanceof boolean[]) {
                boolean result = getBooleanValue(rholder, i);
                boolean check = ((boolean[]) checkArray)[i];
                verify(result == check,
                        "result [" + i + "] " + result + " vs. " + check);
            } else if (checkArray instanceof char[]) {
                char result = getCharValue(rholder, i);
                char check = ((char[]) checkArray)[i];
                verify(result == check,
                        "result [" + i + "] " + result + " vs. " + check);
            } else {
                verify(false, "unknown type for checkArray");
            }
        }
    }

    void checkMatch(MTest test, boolean oneWord) {
        String[] argv;
        if (oneWord) {
            argv = new String[1];
            argv[0] = test.args;
        } else {
            argv = argsFromString(test.args);
        }
        if (test.result instanceof Long) {
            checkMatch(argv, 0, argv.length,
                    ((Long) test.result).longValue(),
                    test.resultIdx);
        } else if (test.result instanceof Double) {
            checkMatch(argv, 0, argv.length,
                    ((Double) test.result).doubleValue(),
                    test.resultIdx);
        } else if (test.result instanceof String) {
            checkMatch(argv, 0, argv.length,
                    (String) test.result,
                    test.resultIdx);
        } else if (test.result instanceof Boolean) {
            checkMatch(argv, 0, argv.length,
                    ((Boolean) test.result).booleanValue(),
                    test.resultIdx);
        } else if (test.result instanceof Character) {
            checkMatch(argv, 0, argv.length,
                    ((Character) test.result).charValue(),
                    test.resultIdx);
        } else if (test.result.getClass().isArray()) {
            checkMatch(argv, 0, argv.length, test.result,
                    test.resultIdx);
        } else if (test.result instanceof MErr) {
            MErr err = (MErr) test.result;
            String argname = parser.getOptionName(argv[0]);
            String msg = "";

            switch (err.code) {
            case 'c': {
                msg = "requires a contiguous value";
                break;
            }
            case 'm': {
                msg = "malformed " + parser.getOptionTypeName(argv[0]) +
                        " '" + err.valStr + "'";
                break;
            }
            case 'r': {
                msg = "value '" + err.valStr + "' not in range " +
                        parser.getOptionRangeDesc(argv[0]);
                break;
            }
            case 'v': {
                msg = "requires " + err.valStr + " values";
                break;
            }
            }
            checkMatch(argv, 0, argname + ": " + msg);
        } else {
            verify(false, "Unknown result type");
        }
    }

    void checkMatches(MTest[] tests, boolean oneWord) {
        for (int i = 0; i < tests.length; i++) {
            checkMatch(tests[i], oneWord);
        }
    }

    Object getMatchResult(String args[], int idx, int cnt,
                   String errMsg, int resultIdx) {
        boolean exceptionThrown = false;
        int k = 0;
        try {
            k = parser.matchArg(args, idx);
        } catch (Exception e) {
            exceptionThrown = true;
            checkException(e, errMsg);
        }
        if (!exceptionThrown) {
            verify(k == idx + cnt,
                    "Expecting result index " + (idx + cnt) + ", got " + k);
            Object result = parser.getResultHolder(args[0]);
            if (resultIdx >= 0) {
                verify(result instanceof Vector,
                        "Expecting result to be stored in a vector");
                Vector<?> vec = (Vector<?>) result;
                verify(vec.size() == resultIdx + 1,
                        "Expecting result vector size " + (resultIdx + 1));
                return vec.get(resultIdx);
            } else {
                return result;
            }
        } else {
            return null;
        }
    }

    /**
     * Runs a set of tests to verify correct operation of the
     * ArgParser class. If all the tests run correctly, the
     * program prints the message <code>Passed</code> and terminates.
     * Otherwise, diagnostic information is printed at the first
     * point of failure.
     */
    public static void main(String[] args) {
        ArgParserTest test = new ArgParserTest();

        BooleanHolder bh = new BooleanHolder();
        boolean[] b3 = new boolean[3];
        CharHolder ch = new CharHolder();
        char[] c3 = new char[3];
        IntHolder ih = new IntHolder();
        int[] i3 = new int[3];
        LongHolder lh = new LongHolder();
        long[] l3 = new long[3];
        FloatHolder fh = new FloatHolder();
        float[] f3 = new float[3];
        DoubleHolder dh = new DoubleHolder();
        double[] d3 = new double[3];
        StringHolder sh = new StringHolder();
        String[] s3 = new String[3];

        test.checkAdd("-foo %i{[0,10)}X3 #sets the value of foo",
                //			   0123456789012345
                i3, 'i', 3, new String[] { "-foo " },
                new RngCheck[] {
                new RngCheck(0, CLOSED, 10, OPEN) },
                "sets the value of foo", null);

        test.checkAdd("-arg1,,", null, "Null option name given");
        test.checkAdd("-arg1,,goo %f ", null, "Null option name given");
        test.checkAdd("  ", null, "Null option name given");
        test.checkAdd("", null, "Null option name given");
        test.checkAdd("  %v", null, "Null option name given");
        test.checkAdd("-foo  ", null, "No conversion character given");
        test.checkAdd("-foo %", null, "No conversion character given");
        test.checkAdd("foo, aaa   bbb ", null, "Names not separated by ','");
        test.checkAdd(" foo aaa %d", null, "Names not separated by ','");
        test.checkAdd("-arg1,-b,", null, "Null option name given");
        test.checkAdd("-arg1,-b", null, "No conversion character given");
        test.checkAdd("-arg1 ", null, "No conversion character given");
        test.checkAdd("-arg1, %v", null, "Null option name given");
        test.checkAdd("-arg1,%v", null, "Null option name given");
        test.checkAdd("-foo %V", null,
                "Conversion code 'V' not one of 'iodxcbfsvh'");
        test.checkAdd("-h %hX5", null, "Multipliers not supported for %h");
        test.checkAdd("-h %h{}", null, "Ranges not supported for %h");
        test.checkAdd("-help, -h %h #here is how we help you",
                null, 'h', 1, new String[] { "-help ", "-h " },
                null, "here is how we help you", null);

        test.checkAdd(
                "-arg1 ,-arg2=%d{0,3,(7,16]}X1 #x3 test",
                l3, 'd', 1, new String[] { "-arg1 ", "-arg2=" },
                new RngCheck[]
           { new RngCheck(0),
                   new RngCheck(3),
                   new RngCheck(7, OPEN, 16, CLOSED),
           },
                "x3 test", null);

        test.checkAdd(
                "bbb,ccc%x{[1,2]} #X3 x3 test",
                l3, 'x', 1, new String[] { "bbb", "ccc" },
                new RngCheck[]
           { new RngCheck(1, CLOSED, 2, CLOSED),
           },
                "X3 x3 test", null);

        test.checkAdd(
                " bbb ,ccc,  ddd  ,e   , f=%bX1 #x3 test",
                b3, 'b', 1, new String[] { "bbb ", "ccc", "ddd ", "e ", "f=" },
                null,
                "x3 test", null);

        test.checkAdd(
                " bbb ,ccc,  ddd  ,e   , f= %bX3 #x3 test",
                b3, 'b', 3, new String[] { "bbb ", "ccc ", "ddd ", "e ", "f= " },
                null,
                "x3 test", null);

        test.checkAdd(
                "-b,--bar %s{[\"john\",\"jerry\"),fred,\"harry\"} #sets bar",
                sh, 's', 1, new String[] { "-b ", "--bar " },
                new RngCheck[] {
                        new RngCheck("jerry", OPEN, "john", CLOSED),
                        new RngCheck("fred"),
                        new RngCheck("harry") },
                "sets bar", null);

        test.checkAdd(
                "-c ,coven%f{0.0,9.0,(6,5],[-9.1,10.2]}  ",
                dh, 'f', 1, new String[] { "-c ", "coven" },
                new RngCheck[] {
                        new RngCheck(0.0),
                        new RngCheck(9.0),
                        new RngCheck(5.0, CLOSED, 6.0, OPEN),
                        new RngCheck(-9.1, CLOSED, 10.2, CLOSED) },
                "", null);

        test.checkAdd(
                "-b %b #a boolean value  ",
                bh, 'b', 1, new String[] { "-b " },
                new RngCheck[] {},
                "a boolean value  ", null);

        test.checkAdd("-a %i", ih, 'i', 1, "-a ", null, "", null);
        test.checkAdd("-a %o", lh, 'o', 1, "-a ", null, "", null);
        test.checkAdd("-a %d", i3, 'd', 1, "-a ", null, "", null);
        test.checkAdd("-a %x", l3, 'x', 1, "-a ", null, "", null);
        test.checkAdd("-a %c", ch, 'c', 1, "-a ", null, "", null);
        test.checkAdd("-a %c", c3, 'c', 1, "-a ", null, "", null);
        test.checkAdd("-a %v", bh, 'v', 1, "-a ", null, "", null);
        test.checkAdd("-a %b", b3, 'b', 1, "-a ", null, "", null);
        test.checkAdd("-a %f", fh, 'f', 1, "-a ", null, "", null);
        test.checkAdd("-a %f", f3, 'f', 1, "-a ", null, "", null);
        test.checkAdd("-a %f", dh, 'f', 1, "-a ", null, "", null);
        test.checkAdd("-a %f", d3, 'f', 1, "-a ", null, "", null);

        test.checkAdd("-a %i", fh, 'i', 1, "-a ", null, "",
                "Invalid result holder for %i");
        test.checkAdd("-a %c", i3, 'c', 1, "-a ", null, "",
                "Invalid result holder for %c");
        test.checkAdd("-a %v", d3, 'v', 1, "-a ", null, "",
                "Invalid result holder for %v");
        test.checkAdd("-a %f", sh, 'f', 1, "-a ", null, "",
                "Invalid result holder for %f");
        test.checkAdd("-a %s", l3, 's', 1, "-a ", null, "",
                "Invalid result holder for %s");

        test.checkAdd("-foo %i{} ", ih, 'i', 1, "-foo ", null, "", null);
        test.checkAdd("-foo%i{}", ih, 'i', 1, "-foo", null, "", null);
        test.checkAdd("-foo%i{  }", ih, 'i', 1, "-foo", null, "", null);
        test.checkAdd("-foo%i{ }}", ih,
                "Illegal character(s), expecting '#'");
        test.checkAdd("-foo%i{  ", ih, "Unterminated range specification");
        test.checkAdd("-foo%i{", ih, "Unterminated range specification");
        test.checkAdd("-foo%i{0,9", ih, "Unterminated range specification");
        test.checkAdd("-foo%i{1,2,3)", ih,
                "Unterminated range specification");

        test.checkAdd("-b %f{0.9}", fh, 'f', 1, "-b ",
                new RngCheck[] { new RngCheck(0.9) },
                "", null);
        test.checkAdd("-b %f{ 0.9 ,7, -0.5,-4 ,6 }", fh, 'f', 1, "-b ",
                new RngCheck[] { new RngCheck(0.9),
                        new RngCheck(7.0),
                        new RngCheck(-0.5),
                        new RngCheck(-4.0),
                        new RngCheck(6.0) },
                "", null);
        test.checkAdd("-b %f{ [0.9,7), (-0.5,-4),[9,6] , (10,13.4] }",
                fh, 'f', 1, "-b ",
                new RngCheck[] { new RngCheck(0.9, CLOSED, 7.0, OPEN),
                        new RngCheck(-4.0, OPEN, -.5, OPEN),
                        new RngCheck(6.0, CLOSED, 9.0, CLOSED),
                        new RngCheck(10.0, OPEN, 13.4, CLOSED),
              },
                "", null);
        test.checkAdd("-b %f{(8 9]}", fh,
                "Missing ',' in subrange specification");
        test.checkAdd("-b %f{(8,9,]}", fh,
                "Unterminated subrange");
        test.checkAdd("-b %f{(8,9 ,]}", fh,
                "Unterminated subrange");
        test.checkAdd("-b %f{(8,9  8]}", fh,
                "Unterminated subrange");
        test.checkAdd("-b %f{8 9}", fh,
                "Range spec: ',' or '}' expected");
        test.checkAdd("-b %f{8 *}", fh,
                "Range spec: ',' or '}' expected");

        test.checkAdd("-b %f{8y}", fh,
                "Range spec: ',' or '}' expected");
        test.checkAdd("-b %f{.}", fh,
                "Malformed float '.}' in range spec");
        test.checkAdd("-b %f{1.0e}", fh,
                "Malformed float '1.0e}' in range spec");
        test.checkAdd("-b %f{[*]}", fh,
                "Malformed float '*' in range spec");
        test.checkAdd("-b %f{1.2e5t}", fh,
                "Range spec: ',' or '}' expected");

        test.checkAdd("-b %i{8}", ih, 'i', 1, "-b ",
                new RngCheck[] { new RngCheck(8) },
                "", null);
        test.checkAdd("-b %i{8, 9,10 }", ih, 'i', 1, "-b ",
                new RngCheck[] { new RngCheck(8),
                        new RngCheck(9),
                        new RngCheck(10) },
                "", null);
        test.checkAdd("-b %i{8, [-9,10),[-17,15],(2,-33),(8,9] }",
                ih, 'i', 1, "-b ",
                new RngCheck[] { new RngCheck(8),
                        new RngCheck(-9, CLOSED, 10, OPEN),
                        new RngCheck(-17, CLOSED, 15, CLOSED),
                        new RngCheck(-33, OPEN, 2, OPEN),
                           new RngCheck(8, OPEN, 9, CLOSED),
              },
                "", null);
        test.checkAdd("-b %i{8.7}", ih,
                "Range spec: ',' or '}' expected");
        test.checkAdd("-b %i{6,[*]}", ih,
                "Malformed integer '*' in range spec");
        test.checkAdd("-b %i{g76}", ih,
                "Malformed integer 'g' in range spec");

        test.checkAdd("-b %s{foobar}", sh, 's', 1, "-b ",
                new RngCheck[] { new RngCheck("foobar") },
                "", null);
        test.checkAdd("-b %s{foobar, 0x233,\"  \"}", sh, 's', 1, "-b ",
                new RngCheck[] { new RngCheck("foobar"),
                        new RngCheck("0x233"),
                        new RngCheck("  ") },
                "", null);
        test.checkAdd("-b %s{foobar,(bb,aa], [\"01\",02]}",
                sh, 's', 1, "-b ",
                new RngCheck[]
                       { new RngCheck("foobar"),
                               new RngCheck("aa", CLOSED, "bb", OPEN),
                               new RngCheck("01", CLOSED, "02", CLOSED),
               },
                "", null);

        test.checkAdd("-b %c{'a'}", ch, 'c', 1, "-b ",
                new RngCheck[] { new RngCheck('a') },
                "", null);
        test.checkAdd("-b %c{'\\n', '\\002', 'B'}", ch, 'c', 1, "-b ",
                new RngCheck[] { new RngCheck('\n'),
                        new RngCheck('\002'),
                        new RngCheck('B') },
                "", null);
        test.checkAdd("-b %c{'q',('g','a'], ['\t','\\003']}",
                ch, 'c', 1, "-b ",
                new RngCheck[]
                       { new RngCheck('q'),
                               new RngCheck('a', CLOSED, 'g', OPEN),
                               new RngCheck('\003', CLOSED, '\t', CLOSED),
               },
                "", null);

        test.checkAdd("-b %b{true}X2", b3, 'b', 2, "-b ",
                new RngCheck[] { new RngCheck(true) },
                "", null);
        test.checkAdd("-b %b{ true , false, true }", bh, 'b', 1, "-b ",
                new RngCheck[] { new RngCheck(true),
                        new RngCheck(false),
                        new RngCheck(true) },
                "", null);
        test.checkAdd("-b %v{true,[true,false)}", bh,
                "Sub ranges not supported for %b or %v");
        test.checkAdd("-b %v{true,[]}", bh,
                "Sub ranges not supported for %b or %v");
        test.checkAdd("-b %b{tru}", bh,
                "Malformed boolean 'tru}' in range spec");

        test.checkAdd("-b %iX2", i3, 'i', 2, "-b ", null, "", null);
        test.checkAdd("-b %vX3", b3, 'v', 3, "-b ", null, "", null);
        test.checkAdd("-b %v{ }X3", b3, 'v', 3, "-b ", null, "", null);

        test.checkAdd("-b=%iX2", i3, 'i', 2, "-b", null, "",
                "Multiplier value incompatible with one word option -b=");
        test.checkAdd("-b %iX0", i3, 'i', 0, "-b ", null, "",
                "Value multiplier number must be > 0");
        test.checkAdd("-b %iX-6", i3, 'i', 0, "-b ", null, "",
                "Value multiplier number must be > 0");
        test.checkAdd("-b %iXy", i3, 'i', 0, "-b ", null, "",
                "Malformed value multiplier");
        test.checkAdd("-b %iX4", i3, 'i', 4, "-b ", null, "",
                "Result holder array must have a length >= 4");
        test.checkAdd("-b %iX4", ih, 'i', 4, "-b ", null, "",
                "Multiplier requires result holder to be an array of length >= 4");

        test.checkAdd("-b %i #X4", ih, 'i', 1, "-b ", null, "X4", null);
        test.checkAdd("-b %i #[}X4", ih, 'i', 1, "-b ", null, "[}X4", null);

        //	   test.checkPrintHelp("");
        //	   test.checkPrintUsage("");

        test = new ArgParserTest();

        test.checkAdd(
                "-intarg %i{1,2,(9,18],[22,27],[33,38),(45,48)} #test int arg",
                ih, 'i', 1, "-intarg ",
                new RngCheck[]
           { new RngCheck(1),
                   new RngCheck(2),
                   new RngCheck(9, OPEN, 18, CLOSED),
                   new RngCheck(22, CLOSED, 27, CLOSED),
                   new RngCheck(33, CLOSED, 38, OPEN),
                   new RngCheck(45, OPEN, 48, OPEN),
           },
                "test int arg", null);

        MTest[] tests;

        tests = new MTest[]
        {
                new MTest("-intarg 1", new Long(1)),
                new MTest("-intarg 3", new MErr('r', "3")),
                new MTest("-intarg 9", new MErr('r', "9")),
                new MTest("-intarg 11", new Long(11)),
                new MTest("-intarg 18", new Long(18)),
                new MTest("-intarg 22", new Long(22)),
                new MTest("-intarg 25", new Long(25)),
                new MTest("-intarg 27", new Long(27)),
                new MTest("-intarg 33", new Long(33)),
                new MTest("-intarg 35", new Long(35)),
                new MTest("-intarg 38", new MErr('r', "38")),
                new MTest("-intarg 45", new MErr('r', "45")),
                new MTest("-intarg 46", new Long(46)),
                new MTest("-intarg 48", new MErr('r', "48")),
                new MTest("-intarg 100", new MErr('r', "100")),
                new MTest("-intarg 0xbeef", new MErr('r', "0xbeef")),
                new MTest("-intarg 0x2f", new Long(0x2f)),
                new MTest("-intarg 041", new Long(041)),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd(
                "-farg %f{1,2,(9,18],[22,27],[33,38),(45,48)} #test float arg",
                dh, 'f', 1, "-farg ",
                new RngCheck[]
           {
                   new RngCheck(1.0),
                   new RngCheck(2.0),
                   new RngCheck(9.0, OPEN, 18.0, CLOSED),
                   new RngCheck(22.0, CLOSED, 27.0, CLOSED),
                   new RngCheck(33.0, CLOSED, 38.0, OPEN),
                   new RngCheck(45.0, OPEN, 48.0, OPEN),
           },
                "test float arg", null);

        tests = new MTest[]
        {
                new MTest("-farg 1", new Double(1)),
                new MTest("-farg 3", new MErr('r', "3")),
                new MTest("-farg 9", new MErr('r', "9")),
                new MTest("-farg 9.0001", new Double(9.0001)),
                new MTest("-farg 11", new Double(11)),
                new MTest("-farg 18", new Double(18)),
                new MTest("-farg 22", new Double(22)),
                new MTest("-farg 25", new Double(25)),
                new MTest("-farg 27", new Double(27)),
                new MTest("-farg 33", new Double(33)),
                new MTest("-farg 35", new Double(35)),
                new MTest("-farg 37.9999", new Double(37.9999)),
                new MTest("-farg 38", new MErr('r', "38")),
                new MTest("-farg 45", new MErr('r', "45")),
                new MTest("-farg 45.0001", new Double(45.0001)),
                new MTest("-farg 46", new Double(46)),
                new MTest("-farg 47.9999", new Double(47.9999)),
                new MTest("-farg 48", new MErr('r', "48")),
                new MTest("-farg 100", new MErr('r', "100")),
                new MTest("-farg 0", new MErr('r', "0")),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd(
                "-sarg %s{1,2,(AA,AZ],[BB,BX],[C3,C8),(d5,d8)} #test string arg",
                s3, 's', 1, "-sarg ",
                new RngCheck[]
           { new RngCheck("1"),
                   new RngCheck("2"),
                   new RngCheck("AA", OPEN, "AZ", CLOSED),
                   new RngCheck("BB", CLOSED, "BX", CLOSED),
                   new RngCheck("C3", CLOSED, "C8", OPEN),
                   new RngCheck("d5", OPEN, "d8", OPEN),
           },
                "test string arg", null);

        tests = new MTest[]
        {
                new MTest("-sarg 1", "1"),
                new MTest("-sarg 3", new MErr('r', "3")),
                new MTest("-sarg AA", new MErr('r', "AA")),
                new MTest("-sarg AM", "AM"),
                new MTest("-sarg AZ", "AZ"),
                new MTest("-sarg BB", "BB"),
                new MTest("-sarg BL", "BL"),
                new MTest("-sarg BX", "BX"),
                new MTest("-sarg C3", "C3"),
                new MTest("-sarg C6", "C6"),
                new MTest("-sarg C8", new MErr('r', "C8")),
                new MTest("-sarg d5", new MErr('r', "d5")),
                new MTest("-sarg d6", "d6"),
                new MTest("-sarg d8", new MErr('r', "d8")),
                new MTest("-sarg zzz", new MErr('r', "zzz")),
                new MTest("-sarg 0", new MErr('r', "0")),
        };
        test.checkMatches(tests, MULTI_WORD);

        test = new ArgParserTest();

        test.checkAdd(
                "-carg %c{1,2,(a,z],['A','Z'],['\\001',\\007),(4,8)}",
                c3, 'c', 1, "-carg ",
                new RngCheck[]
           { new RngCheck('1'),
                   new RngCheck('2'),
                   new RngCheck('a', OPEN, 'z', CLOSED),
                   new RngCheck('A', CLOSED, 'Z', CLOSED),
                   new RngCheck('\001', CLOSED, '\007', OPEN),
                   new RngCheck('4', OPEN, '8', OPEN),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-carg 1", new Character('1')),
                new MTest("-carg 3", new MErr('r', "3")),
                new MTest("-carg a", new MErr('r', "a")),
                new MTest("-carg m", new Character('m')),
                new MTest("-carg z", new Character('z')),
                new MTest("-carg A", new Character('A')),
                new MTest("-carg 'L'", new Character('L')),
                new MTest("-carg 'Z'", new Character('Z')),
                new MTest("-carg \\001", new Character('\001')),
                new MTest("-carg \\005", new Character('\005')),
                new MTest("-carg '\\007'", new MErr('r', "'\\007'")),
                new MTest("-carg '4'", new MErr('r', "'4'")),
                new MTest("-carg 6", new Character('6')),
                new MTest("-carg 8", new MErr('r', "8")),
                new MTest("-carg '\\012'", new MErr('r', "'\\012'")),
                new MTest("-carg 0", new MErr('r', "0")),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd(
                "-foo=%i{[-50,100]}", ih, 'i', 1, "-foo=",
                new RngCheck[]
           { new RngCheck(-50, CLOSED, 100, CLOSED),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-foo=-51", new MErr('r', "-51")),
                new MTest("-foo=-0x32", new Long(-0x32)),
                new MTest("-foo=-0x33", new MErr('r', "-0x33")),
                new MTest("-foo=-0777", new MErr('r', "-0777")),
                new MTest("-foo=-07", new Long(-07)),
                new MTest("-foo=0", new Long(0)),
                new MTest("-foo=100", new Long(100)),
                new MTest("-foo=0x5e", new Long(0x5e)),
                new MTest("-foo=066", new Long(066)),
                new MTest("-foo=06677", new MErr('r', "06677")),
                new MTest("-foo=0xbeef", new MErr('r', "0xbeef")),
                new MTest("-foo=foo", new MErr('m', "foo")),
                new MTest("-foo=-51d", new MErr('m', "-51d")),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-foo2=%i", ih, 'i', 1, "-foo2=", null, "", null);
        tests = new MTest[]
        {
                new MTest("-foo2=-51", new Long(-51)),
                new MTest("-foo2=-0x33", new Long(-0x33)),
                new MTest("-foo2=-0777", new Long(-0777)),
                new MTest("-foo2=06677", new Long(06677)),
                new MTest("-foo2=0xbeef", new Long(0xbeef)),
                new MTest("-foo2=foo", new MErr('m', "foo")),
                new MTest("-foo2=-51d", new MErr('m', "-51d")),
                new MTest("-foo2=-51", new Long(-51)),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-foo3 %iX3", i3, 'i', 3, "-foo3 ", null, "", null);
        tests = new MTest[]
        {
                new MTest("-foo3 -51 678 0x45",
                        new long[] { -51, 678, 0x45 }),
                new MTest("-foo3 55 16f 55", new MErr('m', "16f")),
                new MTest("-foo3 55 16", new MErr('v', "3")),
        };
        test.checkMatches(tests, MULTI_WORD);

        Vector<String> vec = new Vector<String>(100);

        test.checkAdd("-foov3 %iX3", vec, 'i', 3, "-foov3 ", null, "", null);
        tests = new MTest[]
        { new MTest("-foov3 -1 2 4", new long[] { -1, 2, 4 }, 0),
                new MTest("-foov3 10 3 9", new long[] { 10, 3, 9 }, 1),
                new MTest("-foov3 123 1 0", new long[] { 123, 1, 0 }, 2),
        };
        vec.clear();
        test.checkMatches(tests, MULTI_WORD);
        test.checkAdd("-foov %i", vec, 'i', 1, "-foov ", null, "", null);
        tests = new MTest[]
        { new MTest("-foov 11", new Long(11), 0),
                new MTest("-foov 12", new Long(12), 1),
                new MTest("-foov 13", new Long(13), 2),
        };
        vec.clear();
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd(
                "-foo4 %i{[-50,100]}X2", i3, 'i', 2, "-foo4 ",
                new RngCheck[]
           { new RngCheck(-50, CLOSED, 100, CLOSED),
           },
                "", null);
        tests = new MTest[]
        {
                new MTest("-foo4 -49 78",
                        new long[] { -49, 78 }),
                new MTest("-foo4 -48 102", new MErr('r', "102")),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd(
                "-oct=%o{[-062,0144]}", ih, 'o', 1, "-oct=",
                new RngCheck[]
           { new RngCheck(-50, CLOSED, 100, CLOSED),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-oct=-063", new MErr('r', "-063")),
                new MTest("-oct=-0x32", new MErr('m', "-0x32")),
                new MTest("-oct=-0777", new MErr('r', "-0777")),
                new MTest("-oct=-07", new Long(-07)),
                new MTest("-oct=0", new Long(0)),
                new MTest("-oct=100", new Long(64)),
                new MTest("-oct=0xae", new MErr('m', "0xae")),
                new MTest("-oct=66", new Long(066)),
                new MTest("-oct=06677", new MErr('r', "06677")),
                new MTest("-oct=0xbeef", new MErr('m', "0xbeef")),
                new MTest("-oct=foo", new MErr('m', "foo")),
                new MTest("-oct=-51d", new MErr('m', "-51d")),
                new MTest("-oct=78", new MErr('m', "78")),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-oct2=%o", ih, 'o', 1, "-oct2=", null, "", null);
        tests = new MTest[]
        {
                new MTest("-oct2=-063", new Long(-063)),
                new MTest("-oct2=-0777", new Long(-0777)),
                new MTest("-oct2=06677", new Long(06677)),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd(
                "-dec=%d{[-0x32,0x64]}", ih, 'd', 1, "-dec=",
                new RngCheck[]
           { new RngCheck(-50, CLOSED, 100, CLOSED),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-dec=-063", new MErr('r', "-063")),
                new MTest("-dec=-0x32", new MErr('m', "-0x32")),
                new MTest("-dec=-0777", new MErr('r', "-0777")),
                new MTest("-dec=-07", new Long(-07)),
                new MTest("-dec=0", new Long(0)),
                new MTest("-dec=100", new Long(100)),
                new MTest("-dec=0xae", new MErr('m', "0xae")),
                new MTest("-dec=66", new Long(66)),
                new MTest("-dec=06677", new MErr('r', "06677")),
                new MTest("-dec=0xbeef", new MErr('m', "0xbeef")),
                new MTest("-dec=foo", new MErr('m', "foo")),
                new MTest("-dec=-51d", new MErr('m', "-51d")),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-dec2=%d", ih, 'd', 1, "-dec2=", null, "", null);
        tests = new MTest[]
        {
                new MTest("-dec2=-063", new Long(-63)),
                new MTest("-dec2=-0777", new Long(-777)),
                new MTest("-dec2=06677", new Long(6677)),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd(
                "-hex=%x{[-0x32,0x64]}", ih, 'x', 1, "-hex=",
                new RngCheck[]
           { new RngCheck(-50, CLOSED, 100, CLOSED),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-hex=-06", new Long(-0x6)),
                new MTest("-hex=-0x3g2", new MErr('m', "-0x3g2")),
                new MTest("-hex=-0777", new MErr('r', "-0777")),
                new MTest("-hex=-017", new Long(-0x17)),
                new MTest("-hex=0", new Long(0)),
                new MTest("-hex=64", new Long(0x64)),
                new MTest("-hex=5e", new Long(0x5e)),
                new MTest("-hex=66", new MErr('r', "66")),
                new MTest("-hex=06677", new MErr('r', "06677")),
                new MTest("-hex=0xbeef", new MErr('m', "0xbeef")),
                new MTest("-hex=foo", new MErr('m', "foo")),
                new MTest("-hex=-51d", new MErr('r', "-51d")),
                new MTest("-hex=-51g", new MErr('m', "-51g")),
                new MTest("-hex=", new MErr('c', "")),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-hex2=%x", ih, 'x', 1, "-hex2=", null, "", null);
        tests = new MTest[]
        {
                new MTest("-hex2=-0777", new Long(-0x777)),
                new MTest("-hex2=66", new Long(0x66)),
                new MTest("-hex2=06677", new Long(0x6677)),
                new MTest("-hex2=-51d", new Long(-0x51d)),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd(
                "-char=%c{['b','m']}", ch, 'c', 1, "-char=",
                new RngCheck[]
           { new RngCheck('b', CLOSED, 'm', CLOSED),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-char=a", new MErr('r', "a")),
                new MTest("-char=b", new Character('b')),
                new MTest("-char='b'", new Character('b')),
                new MTest("-char='\142'", new Character('b')),
                new MTest("-char='\141'", new MErr('r', "'\141'")),
                new MTest("-char=\142", new Character('b')),
                new MTest("-char=\141", new MErr('r', "\141")),
                new MTest("-char=m", new Character('m')),
                new MTest("-char=z", new MErr('r', "z")),
                new MTest("-char=bb", new MErr('m', "bb")),
                new MTest("-char='b", new MErr('m', "'b")),
                new MTest("-char='", new MErr('m', "'")),
                new MTest("-char=a'", new MErr('m', "a'")),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-char2=%c", ch, 'c', 1, "-char2=", null, "", null);
        tests = new MTest[]
        {
                new MTest("-char2=a", new Character('a')),
                new MTest("-char2='\141'", new Character('\141')),
                new MTest("-char2=\141", new Character('\141')),
                new MTest("-char2=z", new Character('z')),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-charv3 %cX3", vec, 'c', 3, "-charv3 ", null, "", null);
        tests = new MTest[]
        { new MTest("-charv3 a b c", new char[] { 'a', 'b', 'c' }, 0),
                new MTest("-charv3 'g' f '\\n'", new char[] { 'g', 'f', '\n' }, 1),
                new MTest("-charv3 1 \001 3", new char[] { '1', '\001', '3' }, 2),
        };
        vec.clear();
        test.checkMatches(tests, MULTI_WORD);
        test.checkAdd("-charv=%c", vec, 'c', 1, "-charv=", null, "", null);
        tests = new MTest[]
        { new MTest("-charv=d", new Character('d'), 0),
                new MTest("-charv='g'", new Character('g'), 1),
                new MTest("-charv=\111", new Character('\111'), 2),
        };
        vec.clear();
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd(
                "-bool=%b{true}", bh, 'b', 1, "-bool=",
                new RngCheck[]
           { new RngCheck(true),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-bool=true", new Boolean(true)),
                new MTest("-bool=false", new MErr('r', "false")),
                new MTest("-bool=fals", new MErr('m', "fals")),
                new MTest("-bool=falsem", new MErr('m', "falsem")),
                new MTest("-bool=truex", new MErr('m', "truex")),
                new MTest("-bool=foo", new MErr('m', "foo")),
                new MTest("-bool=1", new MErr('m', "1")),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd(
                "-boo2=%b{true,false}", bh, 'b', 1, "-boo2=",
                new RngCheck[]
           { new RngCheck(true),
                   new RngCheck(false),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-boo2=true", new Boolean(true)),
                new MTest("-boo2=false", new Boolean(false)),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-boo3=%b", bh, 'b', 1, "-boo3=", null, "", null);
        tests = new MTest[]
        {
                new MTest("-boo3=true", new Boolean(true)),
                new MTest("-boo3=false", new Boolean(false)),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-boo3 %bX3", b3, 'b', 3, "-boo3 ", null, "", null);
        tests = new MTest[]
        {
                new MTest("-boo3 true false true",
                        new boolean[] { true, false, true }),
                new MTest("-boo3 true fals true", new MErr('m', "fals")),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd("-boov3 %bX3", vec, 'b', 3, "-boov3 ", null, "", null);
        tests = new MTest[]
        { new MTest("-boov3 true true false",
                new boolean[] { true, true, false }, 0),
                new MTest("-boov3 false false true",
                        new boolean[] { false, false, true }, 1),
        };
        vec.clear();
        test.checkMatches(tests, MULTI_WORD);
        test.checkAdd("-boov %b", vec, 'b', 1, "-boov ", null, "", null);
        tests = new MTest[]
        { new MTest("-boov true", new Boolean(true), 0),
                new MTest("-boov false", new Boolean(false), 1),
                new MTest("-boov true", new Boolean(true), 2),
        };
        vec.clear();
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd("-v3 %vX2", b3, 'v', 2, "-v3 ", null, "", null);
        tests = new MTest[]
        { new MTest("-v3", new boolean[] { true, true }),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd(
                "-vf %v{false,true}X2", b3, 'v', 2, "-vf ",
                new RngCheck[]
           { new RngCheck(false),
                   new RngCheck(true),
           },
                "", null);
        tests = new MTest[]
        { new MTest("-vf", new boolean[] { false, false }),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd(
                "-str=%s{(john,zzzz]}", sh, 's', 1, "-str=",
                new RngCheck[]
           { new RngCheck("john", OPEN, "zzzz", CLOSED),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-str=john", new MErr('r', "john")),
                new MTest("-str=joho ", "joho "),
                new MTest("-str=joho ", "joho "),
                new MTest("-str=zzzz", "zzzz"),
                new MTest("-str= joho", new MErr('r', " joho")),
                new MTest("-str=jnhn ", new MErr('r', "jnhn ")),
                new MTest("-str=zzzzz", new MErr('r', "zzzzz")),
                new MTest("-str=\"joho\"", new MErr('r', "\"joho\"")),
                new MTest("-str=\"joho", new MErr('r', "\"joho")),
                new MTest("-str=joho j", "joho j"), // new MErr('m', "joho j")),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-str2=%s", sh, 's', 1, "-str2=", null, "", null);
        tests = new MTest[]
        {
                new MTest("-str2= jnhn", " jnhn"),
                new MTest("-str2=zzzzz", "zzzzz"),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-str3 %sX3", s3, 's', 3, "-str3 ", null, "", null);
        tests = new MTest[]
        {
                new MTest("-str3 foo bar johnny",
                        new String[] { "foo", "bar", "johnny" }),
                new MTest("-str3 zzzzz \"bad foo",
                        new String[] { "zzzzz", "\"bad", "foo"
                }), // new MErr('m', "\"bad")),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd("-strv3 %sX3", vec, 's', 3, "-strv3 ", null, "", null);
        tests = new MTest[]
        { new MTest("-strv3 foo bar \"hihi\"",
                new String[] { "foo", "bar", "\"hihi\"" }, 0),
                new MTest("-strv3 a 123 gg",
                        new String[] { "a", "123", "gg" }, 1),
        };
        vec.clear();
        test.checkMatches(tests, MULTI_WORD);
        test.checkAdd("-strv=%s", vec, 's', 1, "-strv=", null, "", null);
        tests = new MTest[]
        { new MTest("-strv=d", "d", 0),
                new MTest("-strv='g'", "'g'", 1),
                new MTest("-strv=\\111", "\\111", 2),
        };
        vec.clear();
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd(
                "-float=%f{(-0.001,1000.0]}", dh, 'f', 1, "-float=",
                new RngCheck[]
           { new RngCheck(-0.001, OPEN, 1000.0, CLOSED),
           },
                "", null);

        tests = new MTest[]
        {
                new MTest("-float=-0.000999", new Double(-0.000999)),
                new MTest("-float=1e-3", new Double(0.001)),
                new MTest("-float=12.33e1", new Double(123.3)),
                new MTest("-float=1e3", new Double(1e3)),
                new MTest("-float=1000.000", new Double(1000.0)),
                new MTest("-float=-0.001", new MErr('r', "-0.001")),
                new MTest("-float=-1e-3", new MErr('r', "-1e-3")),
                new MTest("-float=1000.001", new MErr('r', "1000.001")),
                new MTest("-float=.", new MErr('m', ".")),
                new MTest("-float=  124.5 ", new Double(124.5)),
                new MTest("-float=124.5x", new MErr('m', "124.5x")),
                new MTest("-float= foo ", new MErr('m', " foo ")),
                new MTest("-float=1e1", new Double(10)),
                new MTest("-float=1e ", new MErr('m', "1e ")),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-float2=%f", dh, 'f', 1, "-float2=", null, "", null);
        tests = new MTest[]
        {
                new MTest("-float2=-0.001", new Double(-0.001)),
                new MTest("-float2=-1e-3", new Double(-1e-3)),
                new MTest("-float2=1000.001", new Double(1000.001)),
        };
        test.checkMatches(tests, ONE_WORD);

        test.checkAdd("-f3 %fX3", d3, 'f', 3, "-f3 ", null, "", null);
        tests = new MTest[]
        {
                new MTest("-f3 -0.001 1.23e5 -9.88e-4",
                        new double[] { -0.001, 1.23e5, -9.88e-4 }),
                new MTest("-f3 7.88 foo 9.0", new MErr('m', "foo")),
                new MTest("-f3 7.88 . 9.0", new MErr('m', ".")),
                new MTest("-f3 7.88 3.0 9.0x", new MErr('m', "9.0x")),
        };
        test.checkMatches(tests, MULTI_WORD);

        test.checkAdd("-fv3 %fX3", vec, 'f', 3, "-fv3 ", null, "", null);
        tests = new MTest[]
        { new MTest("-fv3 1.0 3.444 6.7",
                new double[] { 1.0, 3.444, 6.7 }, 0),
                new MTest("-fv3 13e-5 145.678 0.0001e45",
                        new double[] { 13e-5, 145.678, 0.0001e45 }, 1),
                new MTest("-fv3 11.11 3.1245 -1e-4",
                        new double[] { 11.11, 3.1245, -1e-4 }, 2),
                new MTest("-fv3 1.0 2 3",
                        new double[] { 1.0, 2.0, 3.0 }, 3),
        };
        vec.clear();
        test.checkMatches(tests, MULTI_WORD);
        test.checkAdd("-fv %f", vec, 'f', 1, "-fv ", null, "", null);
        tests = new MTest[]
        { new MTest("-fv -15.1234", new Double(-15.1234), 0),
                new MTest("-fv -1.234e-7", new Double(-1.234e-7), 1),
                new MTest("-fv 0.001111", new Double(0.001111), 2),
        };
        vec.clear();
        test.checkMatches(tests, MULTI_WORD);

        IntHolder intHolder = new IntHolder();
        StringHolder strHolder = new StringHolder();

        ArgParser parser = new ArgParser("test");
        parser.addOption("-foo %d #an int", intHolder);
        parser.addOption("-bar %s #a string", strHolder);
        args = new String[]
          { "zzz", "-cat", "-foo", "123", "yyy", "-bar", "xxxx", "xxx"
          };

        String[] unmatchedCheck = new String[]
          { "zzz", "-cat", "yyy", "xxx"
          };

        String[] unmatched = parser.matchAllArgs(args, 0, 0);
        test.checkStringArray(
                "Unmatched args:", unmatched, unmatchedCheck);

        vec.clear();
        for (int i = 0; i < args.length;) {
            try {
                i = parser.matchArg(args, i);
                if (parser.getUnmatchedArgument() != null) {
                    vec.add(parser.getUnmatchedArgument());
                }
            } catch (Exception e) {
            }
        }
        unmatched = (String[]) vec.toArray(new String[0]);
        test.checkStringArray(
                "My unmatched args:", unmatched, unmatchedCheck);

        System.out.println("\nPassed\n");

    }
}
