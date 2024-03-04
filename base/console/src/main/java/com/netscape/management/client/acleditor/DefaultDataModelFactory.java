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
import com.netscape.management.client.acl.LdapACL;
import com.netscape.management.client.acl.LdapACLSelector;
import com.netscape.management.client.acl.Rule;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.ResourceSet;

/**
 * The DefaultDataModelFactory provides the standard data
 * models for the ACL Editor.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 10/12/97
 */

public class DefaultDataModelFactory implements DataModelFactory,
ACLEditorConstants {
    /**
      * The default ResourceSet for ACL Editor data models.
      */
    public static ResourceSet defaultResourceSet = new ResourceSet("com.netscape.management.client.acleditor.ACLResources");

    /**
     * Get the ACL Rule Table Data Model.
     *
     * @param ds a ConsoleInfo object for the ACL Editor session.
     * @return a DataModelAdapter object.
     */
    public DataModelAdapter getTableDataModel(ConsoleInfo ds,
            WindowFactory wf) {
        return new TableDataModel(this, wf, ds);
    }

    /**
      * Get the ACL Inherited Rule Table Data Model.
      *
      * @param ci a ConsoleInfo object for the ACL Editor session.
      * @return a DataModelAdapter object, or null if inherited rules
      *  are not available for this ACL.
      */
    public DataModelAdapter getInheritedTableDataModel(ConsoleInfo ci) {
        // 3/13/98 DT - Inherited rules not currently used.
        //return new InheritedTableDataModel(this, ci);
        return null;
    }

    /**
      * Get the Hosts Selection Data Model.
      *
      * @param rule the ACL Rule object to be modified.
      * @return a DataModelAdapter object.
      */
    public DataModelAdapter getHostsDataModel(Rule rule) {
        return new HostsDataModel(getResourceSet(), HostsName, rule);
    }

    /**
      * Get the User/Group Selection Data Model.
      *
      * @param rule the ACL Rule object to be modified.
      * @return a DataModelAdapter object.
      */
    public DataModelAdapter getUserGroupDataModel(Rule rule) {
        return new UserGroupDataModel(getResourceSet(), UserGroupName,
                rule);
    }

    /**
      * Get the Rights Selection Data Model.
      *
      * @param rule the ACL Rule object to be modified.
      * @return a DataModelAdapter object.
      */
    public DataModelAdapter getRightsDataModel(Rule rule) {
        return new RightsDataModel(getResourceSet(), RightsName, rule);
    }

    /**
      * Get the ResourceSet for this session of the ACL Editor.
      *
      * @return an ResourceSet object.
      */
    public ResourceSet getResourceSet() {
        return defaultResourceSet;
    }

    protected ACL acl = null;

    /**
     * Get the ACL object for this session of the ACL Editor.
     *
     * @param ci a ConsoleInfo object for the ACL Editor session.
     * @param wf a WindowFactory object for the ACL Editor session.
     * @return an ACL object.
     */
    public ACL getACL(ConsoleInfo ci, WindowFactory wf) {
        if (acl != null)
            return acl;

        String ssl = (String)ci.get("ldapSecurity");
        boolean fSSL = ( (ssl != null) && ssl.equals("on") );

        return (acl = new LdapACL(ci.getHost(), ci.getPort(), fSSL,
                ci.getAuthenticationDN(), ci.getAuthenticationPassword(),
                (LdapACLSelector)(wf.createACLSelectorWindow(null))));
    }

    /**
      * Get the ACL object reference to be passed to the retrieve and update
      * methods of the ACL.
      *
      * @param ci a ConsoleInfo object for the ACL Editor session.
      * @return a Object ACL reference.
      */
    public Object getACLRef(ConsoleInfo ci) {
        return ci.getAclDN();
    }
}
