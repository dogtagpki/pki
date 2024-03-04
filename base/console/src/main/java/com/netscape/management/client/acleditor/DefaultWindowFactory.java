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

import com.netscape.management.client.acl.ACL;
import com.netscape.management.client.acl.Rule;
import com.netscape.management.client.util.Help;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.console.ConsoleInfo;

/**
 * The DefaultWindowFactory provides the standard window
 * implementations for the ACL Editor.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 10/14/97
 */

public class DefaultWindowFactory implements WindowFactory,
ACLEditorConstants {
    public DefaultWindowFactory() { }

    /**
      * The default ResourceSet for ACL Editor windows.
      */
    public static ResourceSet defaultResourceSet = new ResourceSet("com.netscape.management.client.acleditor.ACLResources");

    /**
     * The session identifier for this ACL Editor session.
     */
    public static Help defaultHelp = null;

    /**
     * The session identifier for this ACL Editor session.
     */
    public String sessionIdentifier = "<not specified>";

    /**
     * Creates a DefaultWindowFactory object with the
     * specified session identifier.
     *
     * @param id the session identifier.
     * @return a DefaultWindowFactory object.
     */
    public DefaultWindowFactory(String id) {
        sessionIdentifier = id;
    }

    /**
      * Get the ResourceSet for this session of the ACL Editor.
      *
      * @return an ResourceSet object.
      */
    public ResourceSet getResourceSet() {
        return defaultResourceSet;
    }

    /**
      * Get the Help object for this session of the ACL Editor.
      *
      * @return a Help object.
      */
    public Help getHelp() {
        if (defaultHelp != null)
            return defaultHelp;

        return (defaultHelp = new Help(getResourceSet()));
    }

    /**
      * Get the session identifier for this session of the ACL Editor.
      * Examples of a session identifier are: the ACL entry DN, a
      * descriptive label for the resource, or any String to be populated
      * into window titles and instructions as the contextual selection.
      *
      * @return a String object.
      */
    public String getSessionIdentifier() {
        return sessionIdentifier;
    }

    /**
      * Set the session identifier for this session of the ACL Editor.
      * Examples of a session identifier are: the ACL entry DN, a
      * descriptive label for the resource, or any String to be populated
      * into window titles and instructions as the contextual selection.
      *
      * @return a String object.
      */
    public void setSessionIdentifier(String id) {
        sessionIdentifier = id;
    }

    /**
      * Create the Users/Groups Selection Window
      *
      * @return an ACLEditorWindow object.
      */
    public ACLEditorWindow createUserGroupWindow(DataModelAdapter dma,
            ConsoleInfo ci) {
        return new PickerWindow(UserGroupName, this, dma, ci);
    }

    /**
      * Create the Hosts/IP Selection Window
      *
      * @return an ACLEditorWindow object.
      */
    public ACLEditorWindow createHostsWindow(DataModelAdapter dma,
            ConsoleInfo ci) {
        return new PickerWindow(HostsName, this, dma, ci);
    }

    /**
      * Create the Rights Selection Window
      *
      * @return an ACLEditorWindow object.
      */
    public ACLEditorWindow createRightsWindow(DataModelAdapter dma) {
        return new RightsWindow(RightsName, this, dma);
    }

    /**
      * Create the Time Selection Window
      *
      * @return an ACLEditorWindow object.
      */
    public ACLEditorWindow createTimeWindow(Rule rule) {
        return new TimeWindow(TimeName, this, rule);
    }

    /**
      * Create the Syntax Selection Window
      *
      * @return an ACLEditorWindow object.
      */
    public ACLEditorWindow createSyntaxWindow(ACL acl) {
        return new SyntaxWindow(SyntaxName, this, acl);
    }

    /**
      * Create the Attributes Selection Window
      *
      * @return an ACLEditorWindow object.
      */
    public ACLEditorWindow createAttributesWindow(ACL acl) {
        return new AttributesWindow(AttributesName, this, acl);
    }

    /**
      * Create the Test ACL Window
      *
      * @return an ACLEditorWindow object.
      */
    public ACLEditorWindow createTestACLWindow(ConsoleInfo ci,
            Object aclRef) {
        System.err.println("Test ACL Window unimplemented");
        return null;
    }

    protected ACLEditorWindow selectorWindow = null;

    /**
     * Create the ACL Selector Window
     *
     * @return an ACLEditorWindow object.
     */
    public ACLEditorWindow createACLSelectorWindow(ACLEditor session) {
        if (selectorWindow != null)
            return selectorWindow;

        return (selectorWindow = new ACLSelectorWindow(session));
    }

    /**
      * Create the ACL Rule Table Window
      *
      * @return an ACLEditorWindow object.
      */
    public ACLEditorWindow createACLRuleTableWindow(ACLEditor session) {
        return new ACLRuleTableWindow(session.getConsoleInfo(),
                session.getDataModelFactory(),
                session.getWindowFactory(), session.getSessionLabel());
    }
}
