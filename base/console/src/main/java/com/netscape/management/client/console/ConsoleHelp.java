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
package com.netscape.management.client.console;

import com.netscape.management.client.util.Help;

/**
 * This class provides a helper method to invoke
 * help that is specific to Console.
 * 
 * This class is not intended for use by other servers,
 * but due to Java package access rules, it needs to 
 * be declared public.
 * 
 * @see com.netscape.management.client.util#Help
 */
public class ConsoleHelp
{
	private final static String PRODUCT = "admin";

	/**
	 * Displays User Guide help for Console.
	 * 
	 * This call is a convenience method for:
	 * Help.showContextHelp("admin", "topic")
	 * 
	 * @param topic		the help topic contained in tokens.map
	 */
	public static void showHelp(String topic)
	{
		Help.showHelp(PRODUCT, topic);
	}

	
	
	/**
	 * Displays context help for Console.
	 * 
	 * This call is a convenience method for:
	 * Help.showContextHelp("admin", "topic")
	 * 
	 * @param topic		the help topic contained in tokens.map
	 */
	public static void showContextHelp(String topic)
	{
		Help.showContextHelp(PRODUCT, topic);
	}
}
