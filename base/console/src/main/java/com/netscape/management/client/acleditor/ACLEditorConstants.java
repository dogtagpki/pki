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
package com.netscape.management.client.acleditor;

/**
 * Internal global constants for the ACL Editor package.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.3 5/11/98
 *
 * @see com.netscape.management.client.acleditor
 * @see com.netscape.management.client.acl
 */
public interface ACLEditorConstants {
    public static String TableName = "table";
    public static String ACLName = "acl";
    public static String MainWindowName = "main";
    public static String UserGroupName = "userGroup";
    public static String HostsName = "hosts";
    public static String RightsName = "rights";
    public static String TimeName = "time";
    public static String SyntaxName = "syntax";
    public static String AttributesName = "attributes";
    public static String ACLSelectorName = "aclselector";
    public static String HelpDirName = "AclEditorHelp";

    public static final int PAD = 10;
    public static final int LINE_LENGTH = 50;

    public static final int RuleColumnWidth = 40;
    public static final int AllowDenyColumnWidth = 80;
    public final static int addTextWidth = 25;
}
