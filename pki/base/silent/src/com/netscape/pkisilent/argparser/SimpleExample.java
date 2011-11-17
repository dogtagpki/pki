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
 * Gives a very simple example of the use of 
 * {@link argparser.ArgParser ArgParser}.
 */
public class SimpleExample
{
	/**
	 * Run this to invoke command line parsing.
	 */
	public static void main (String[] args) 
	 {
	   // create holder objects for storing results ...
 
	   DoubleHolder theta = new DoubleHolder();
	   StringHolder fileName = new StringHolder();
	   BooleanHolder debug = new BooleanHolder();
 
	   // create the parser and specify the allowed options ...
 
	   ArgParser parser = new ArgParser("java argparser.SimpleExample");
	   parser.addOption ("-theta %f #theta value (in degrees)", theta); 
	   parser.addOption ("-file %s #name of the operating file", fileName);
	   parser.addOption ("-debug %v #enables display of debugging info",
			     debug);

	   // and then match the arguments

	   parser.matchAllArgs (args);

	   // now print out the values

	   System.out.println ("theta=" + theta.value);
	   System.out.println ("fileName=" + fileName.value);
	   System.out.println ("debug=" + debug.value);
	 }
}

