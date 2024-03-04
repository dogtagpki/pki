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

import com.netscape.management.client.console.ConsoleInfo;

/**
 * The ACLEditor class is the functional API for invoking ACL Editor
 * sessions. It is assumed that multiple editing sessions may be
 * spawned concurrently. The internal behaviors of the ACL Editor
 * data tables and the internal ACL format can be customized via the
 * DataModelFactory class and the acl package. The contents of the
 * various windows can be customized via the WindowFactory class.
 * You do not need to call show() on an instance of ACLEditor; a thread
 * is created to populate the ACL data, and the window will be raised
 * when the data has been received and processed.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.3 5/11/98
 *
 * @see DataModelFactory
 * @see WindowFactory
 * @see com.netscape.management.client.acl.ACL
 * @see com.netscape.management.client.acl.Rule
 */
public class ACLEditor implements Runnable {
    protected Thread thread;
    protected ConsoleInfo info;
    protected DataModelFactory dataFactory;
    protected WindowFactory windowFactory;
    protected String windowLabel;

    /**
     * Initializes an ACL Editor session.
     *
     * @param ci the ConsoleInfo object for the ACL Editor session, from
     *  which the ACL DN is pulled.
     */
    public ACLEditor(ConsoleInfo ci) {
        this(ci, new DefaultDataModelFactory(),
                new DefaultWindowFactory(ci.getAclDN()), ci.getAclDN());
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param ci the ConsoleInfo object for the ACL Editor session, from
      *  which the ACL DN is pulled.
      * @param windowLabel a String to be used as the session identifier,
      *  instead of the ACL DN.
      */
    public ACLEditor(ConsoleInfo ci, String windowLabel) {
        this(ci, new DefaultDataModelFactory(),
                new DefaultWindowFactory(windowLabel), windowLabel);
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param ci the ConsoleInfo object for the ACL Editor session, from
      *  which the ACL DN is pulled.
      * @param dmf a DataModelFactory to be used in place of the default
      *  DataModelFactory.
      */
    public ACLEditor(ConsoleInfo ci, DataModelFactory dmf) {
        this(ci, dmf, new DefaultWindowFactory(ci.getAclDN()),
                ci.getAclDN());
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param ci the ConsoleInfo object for the ACL Editor session, from
      *  which the ACL DN is pulled.
      * @param wf a WindowFactory to be used in place of the default
      *  WindowFactory.
      */
    public ACLEditor(ConsoleInfo ci, WindowFactory wf) {
        this(ci, new DefaultDataModelFactory(), wf, ci.getAclDN());
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param ci the ConsoleInfo object for the ACL Editor session, from
      *  which the ACL DN is pulled.
      * @param windowLabel a String to be used as the session identifier,
      *  instead of the ACL DN.
      * @param dmf a DataModelFactory to be used in place of the default
      *  DataModelFactory.
      */
    public ACLEditor(ConsoleInfo ci, String windowLabel,
            DataModelFactory dmf) {
        this(ci, dmf, new DefaultWindowFactory(windowLabel), windowLabel);
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param ci the ConsoleInfo object for the ACL Editor session, from
      *  which the ACL DN is pulled.
      * @param windowLabel a String to be used as the session identifier,
      *  instead of the ACL DN.
      * @param wf a WindowFactory to be used in place of the default
      *  WindowFactory.
      */
    public ACLEditor(ConsoleInfo ci, String windowLabel, WindowFactory wf) {
        this(ci, new DefaultDataModelFactory(), wf, windowLabel);
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param ci the ConsoleInfo object for the ACL Editor session, from
      *  which the ACL DN is pulled.
      * @param dmf a DataModelFactory to be used in place of the default
      *  DataModelFactory.
      * @param wf a WindowFactory to be used in place of the default
      *  WindowFactory.
      */
    public ACLEditor(ConsoleInfo ci, DataModelFactory dmf,
            WindowFactory wf) {
        this(ci, dmf, wf, ci.getAclDN());
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param ci the ConsoleInfo object for the ACL Editor session, from
      *  which the ACL DN is pulled.
      * @param dmf a DataModelFactory to be used in place of the default
      *  DataModelFactory.
      * @param label a String to be used as the session identifier,
      *  instead of the ACL DN.
      */
    public ACLEditor(ConsoleInfo ci, DataModelFactory dmf,
            WindowFactory wf, String label) {
        info = ci;
        dataFactory = dmf;
        windowFactory = wf;
        windowLabel = label;

        thread = new Thread(this);
        thread.start();
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param dsHost the DNS hostname of the LDAP server to contact.
      * @param dsPort the TCP port of the LDAP server to contact.
      * @param bindDN the user DN to bind to the LDAP server.
      * @param bindPW the bind password for the user DN.
      * @param searchBaseDN the base DN for searching for users and groups.
      * @param entryDN the DN of the entry in which ACI attributes will be edited.
      */
    public ACLEditor(String dsHost, int dsPort, String bindDN,
            String bindPW, String searchBaseDN, String entryDN) {
        info = new ConsoleInfo(dsHost, dsPort, bindDN, bindPW,
                searchBaseDN);
        info.setAclDN(entryDN);
        info.setUserGroupDN(searchBaseDN);

        dataFactory = new DefaultDataModelFactory();
        windowFactory = new DefaultWindowFactory(entryDN);
        windowLabel = entryDN;

        thread = new Thread(this);
        thread.start();
    }

    /**
      * Initializes an ACL Editor session.
      *
      * @param dsHost the DNS hostname of the LDAP server to contact.
      * @param dsPort the TCP port of the LDAP server to contact.
      * @param bindDN the user DN to bind to the LDAP server.
      * @param bindPW the bind password for the user DN.
      * @param searchBaseDN the base DN for searching for users and groups.
      * @param entryDN the DN of the entry in which ACI attributes will be edited.
      * @param dmf a DataModelFactory to be used in place of the default DataModelFactory.
      * @param wf a WindowFactory to be used in place of the default WindowFactory.
      * @param label a String to be used as the session identifier, instead of the ACL DN.
      */
    public ACLEditor(String dsHost, int dsPort, String bindDN,
            String bindPW, String searchBaseDN, String entryDN,
            DataModelFactory dmf, WindowFactory wf, String label) {
        info = new ConsoleInfo(dsHost, dsPort, bindDN, bindPW,
                searchBaseDN);
        info.setAclDN(entryDN);
        info.setUserGroupDN(searchBaseDN);

        dataFactory = dmf;
        windowFactory = wf;
        windowLabel = label;

        thread = new Thread(this);
        thread.start();
    }

    /**
      * Does the core work to create the ACL Editor Session, to isolate the caller thread
      * from blocking.
      *
      */
    public void run() {
        ACLSelectorWindow asw = (ACLSelectorWindow)
                (windowFactory.createACLSelectorWindow(this));
        dataFactory.getACL(info,
                windowFactory).retrieveACL(dataFactory.getACLRef(info));
        if (!asw.isError())
            windowFactory.createACLRuleTableWindow(this).show();
    }

    protected ConsoleInfo getConsoleInfo() {
        return info;
    }
    protected DataModelFactory getDataModelFactory() {
        return dataFactory;
    }
    protected WindowFactory getWindowFactory() {
        return windowFactory;
    }
    protected String getSessionLabel() {
        return windowLabel;
    }

    public void show() { } // placeholder...does nothing.
}
