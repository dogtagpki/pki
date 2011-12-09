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
import java.io.IOException;

/** 
  * Exception class used by <code>ArgParser</code> when
  * command line arguments contain an error.
  * 
  * @author John E. Lloyd, Fall 2004
  * @see ArgParser
  */
public class ArgParseException extends IOException
{
	/**
     *
     */
    private static final long serialVersionUID = -604960834535589460L;

    /**
	  * Creates a new ArgParseException with the given message. 
	  * 
	  * @param msg Exception message
	  */
	public ArgParseException (String msg)
	 { super (msg);
	 }

	/** 
	  * Creates a new ArgParseException from the given
	  * argument and message. 
	  * 
	  * @param arg Offending argument
	  * @param msg Error message
	  */
	public ArgParseException (String arg, String msg)
	 { super (arg + ": " + msg);
	 }
}
