import java.util.*;
import java.io.*;
import java.net.*;

import java.security.*;
import java.security.cert.*;
import sun.misc.*;
import netscape.security.x509.*;
import netscape.security.util.*;


public class Utilities
{
	private static final String keyValueSeparators = "=: \t\r\n\f";
	private static final String strictKeyValueSeparators = "=:";
	private static final String specialSaveChars = " \t\r\n\f";
	private static final String whiteSpaceChars = " \t\r\n\f";

	public Utilities()
	{
		// Do nothing
	}

	public String cleanupQuotes(String token) 
	{

		StringBuffer buf = new StringBuffer();
		int length = token.length();
		int curIndex = 0;
		if (token.startsWith("\"") && token.endsWith("\"")) 
		{
			curIndex = 1;
			length--;
		}

		boolean oneQuoteFound = false;
		boolean twoQuotesFound = false;

		while (curIndex < length) 
		{
			char curChar = token.charAt(curIndex);
			if (curChar == '"') 
			{
				twoQuotesFound = (oneQuoteFound) ? true : false;
				oneQuoteFound = true;
			}
			else
			{
				oneQuoteFound = false;
				twoQuotesFound = false;
			}

			if (twoQuotesFound)
			{
				twoQuotesFound = false;
				oneQuoteFound = false;
				curIndex++;
				continue;
			}

			buf.append(curChar);
			curIndex++;
		}

		return buf.toString();
	}

	public String removechar(String token )
	{

		StringBuffer buf = new StringBuffer();
		int end = token.length();
		int begin = 0;
		
		if(token.endsWith(";"))
			end--;

		while(begin < end )
		{
			char curChar = token.charAt(begin);
			buf.append(curChar);
			begin++;
		}
		return buf.toString();

	}
}
