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
package com.netscape.management.client.security;
import java.io.StreamTokenizer;
import java.io.StringReader;
import java.util.Hashtable;
import java.util.Vector;

class Parser extends Vector{
    public Parser(String unparsedString) {
        super();
        //parse the certificate here
        try {
            StreamTokenizer stTokenizer = new StreamTokenizer(new StringReader(unparsedString));
            /*stTokenizer.ordinaryChar('&');
            stTokenizer.ordinaryChar('-');
            stTokenizer.ordinaryChar('_');
            stTokenizer.ordinaryChar(',');
            stTokenizer.ordinaryChar(';');
            stTokenizer.ordinaryChar('.');
            stTokenizer.ordinaryChar('#');
            stTokenizer.ordinaryChar(':');
            stTokenizer.ordinaryChar('/');
            stTokenizer.ordinaryChar(' ');
	    stTokenizer.wordChars('0', '9');*/
	    stTokenizer.resetSyntax();

            tokenizer(stTokenizer);
            //setCertList(new certTokenizer(tokenizer(stTokenizer)));
        } catch (Exception e) {
	    SecurityUtil.printException("Parser::Parser(...)",e);
        }
    }

    //public Vector getTokenList() {
    //    return tokenizer(stTokenizer);
    //}

    void/*Vector*/ tokenizer(StreamTokenizer tokenizer) {
        boolean tokenStart = false;
        StringBuffer token = new StringBuffer();
        //Vector tokenList = new Vector()
        try {
            while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
                if (((char)(tokenizer.ttype) == '\t') ||
                    ((char)(tokenizer.ttype) == '\n') /*||
                    ((char)(tokenizer.ttype) == '/')*/) {
                    //drop the character
                } else if (tokenizer.ttype == '<') {
                    if ((/*tokenList.*/size() != 0) && (token.length() > 0)) {
                        /*tokenList.*/addElement(token.toString());
                    }
                    token = new StringBuffer();
                    tokenStart = true;
                    token.append((Character.valueOf((char)(tokenizer.ttype))).toString());
                } else if (tokenStart && (tokenizer.ttype == '>')) {
                    tokenStart = false;
                    token.append((Character.valueOf((char)(tokenizer.ttype))).toString());
                    /*tokenList.*/addElement(token.toString());
                    token = new StringBuffer();
                } else if (tokenizer.ttype == StreamTokenizer.TT_WORD) {
                    token.append(tokenizer.sval);
                /*} else if (tokenizer.ttype == tokenizer.TT_NUMBER) {
                    token.append((int)tokenizer.nval);*/
                } else {
                    token.append((Character.valueOf((char)(tokenizer.ttype))).toString());
                }
            }
        } catch (Exception e) {
	    SecurityUtil.printException("Parser::tokenizer(...)",e);
        }

        //return tokenList;
    }


    int index = 0;
    public String peek(int by) {
	return index<size()?(String)elementAt(index+by):null;
    }

    public void advanceBy(int by) {
	index += by;
    }
    public String nextToken() {
	index++;
	return (String)(elementAt(index-1));
    }

    public boolean hasMoreElement() {
	return index<size();
    }

    boolean isKeyWord(String key) {
        return (key.startsWith("<") && key.endsWith(">"));
    }


    public Hashtable getTokenObject(String typeKeyword) {
	StringBuffer endKeyword = new StringBuffer();
	endKeyword.append(typeKeyword.substring(0,1));
	endKeyword.append("/");
	endKeyword.append(typeKeyword.substring(1,typeKeyword.length()));
	Hashtable cert = new Hashtable();

	String token = "", endToken = "";
	try{
	    int i=0;
	    while (hasMoreElement()  && !((token = nextToken()).equals(endKeyword.toString()))) {
		endToken = peek(1);
		if (endToken == null) break;
		if (endToken.endsWith(token.substring(1, token.length()))) {
		    cert.put(token.substring(1, token.length()-1), nextToken());
		    advanceBy(1);
		} else {
		    cert.put(token.substring(1,token.length()-1), getTokenObject(token));
		}
	    }
	} catch (Exception e) {
	    cert.put(token.substring(1, token.length()-1), new Hashtable());
	    SecurityUtil.printException("Parser::getTokenObject(...)",e);
	}

	return cert;
    }
}

