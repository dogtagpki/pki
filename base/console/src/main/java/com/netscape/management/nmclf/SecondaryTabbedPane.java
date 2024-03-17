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
package com.netscape.management.nmclf;

import javax.swing.JTabbedPane;

/**
 * A tabbed pane that appears within a tabbed pane.
 * The UI for these set of tabs is different than a normal tabbed pane.
 * Server consoles might use this when there are tabs
 * in the right hand panel of a tree node.
 *
 * Note: This calss is used by AS Console 6.0x and need to be kept.
 *
 * @deprecated use JTabbedPane instead
 */
@Deprecated
public class SecondaryTabbedPane extends JTabbedPane {
}


