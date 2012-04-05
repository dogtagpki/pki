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
package com.netscape.admin.certsrv;

import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;

/**
 * Netscape Certificate Server 4.0 UI Framework
 *
 * This class is responsible for the loading of UI components associated with
 * the certificate server.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @date	 	03/30/97
 */
public class CMSUIFramework {

    /*==========================================================
     * variables
     *==========================================================*/
    private ConsoleInfo mConsoleInfo;       // global information
    private CMSServerInfo mServerInfo;		// server-specific information
    private CMSPageFeeder mPageFeeder;      // KP PageFeeder
    private Framework mFramework;           // KP Framework
    private ISubSystemLocator mSubSystemLocator = null;     // subsystem locator
    private UILoaderRegistry mUILoaders;

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSUIFramework(ConsoleInfo info, CMSServerInfo serverInfo)
        throws EAdminException
    {
        mConsoleInfo = info;
        mServerInfo = serverInfo;
        mPageFeeder = new CMSPageFeeder(info, serverInfo);
        setSubSystemLocator( new HTTPSSubSystemLocator(serverInfo.getAdmin()));
        init();
        //framework must be created as the last components
        //we are not able to change the components of the
        //pages after creating the framework.
        mFramework = new Framework(mPageFeeder);
        mPageFeeder.expendPages();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void setSubSystemLocator(ISubSystemLocator locator) {
        mSubSystemLocator = locator;
    }

    public IPage getPage(String type, String name) throws EAdminException {
        return mPageFeeder.getPage(type, name);
    }

    public Framework getFramework() {
        return mFramework;
    }

    public boolean isNTEnv() throws EAdminException {
        Debug.println("CMSUIFramework - isNTEnv()");
        NameValuePairs response;
        AdminConnection conn = mServerInfo.getAdmin();
        response = conn.search(DestDef.DEST_SERVER_ADMIN,
          ScopeDef.SC_PLATFORM, new NameValuePairs());
        if (response == null)
            throw new EAdminException("PROTOCOL_ERROR",false);
        if (response.get(Constants.PR_NT).equals(Constants.TRUE))
            return true;
        return false;
    }

    /*==========================================================
	 * private methods
     *==========================================================*/
    private void init() throws EAdminException {
        //initialize the kernel UI
        CMSKernelUILoader kernelUI = new CMSKernelUILoader(this);
        kernelUI.register();

        //load subsystem information. if no locator specified use default
        if (mSubSystemLocator == null)
            mSubSystemLocator = new DefaultSubSystemLocator();
        SubSystemInfo[] subsystems = mSubSystemLocator.getInstalledSubSystem();

        //delegate UI loading to each subsystem loader
        UILoaderRegistry registry = new UILoaderRegistry(this);
        Vector subsystemList = new Vector();
        for (int i=0; i< subsystems.length; i++) {
            try {
                subsystemList.addElement(subsystems[i].mType);
                ISubSystemUILoader loader = registry.getUILoader(subsystems[i].mType);
                loader.register();
            } catch (Exception e) {
                Debug.println("Error loading subsystem UI - "+e.toString());
            }
        }

       //set subsystem setting
       mServerInfo.setInstalledSubsystems(subsystemList);
    }

}

//=====================================================================

/**
 * Registry for the Subsystem UI loader.
 * Only single instance of the UI loader should be created.
 */
class UILoaderRegistry {
    private final String PREFIX = "UILOADERREGISTRY_";
    private Hashtable mContent = new Hashtable();
    private ResourceBundle mResource;       // resource boundle

    public UILoaderRegistry(CMSUIFramework uiFramework) {
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mContent.put(Constants.PR_CA_INSTANCE,new CMSCAUILoader(uiFramework));
        mContent.put(Constants.PR_KRA_INSTANCE,new CMSEAUILoader(uiFramework));
        mContent.put(Constants.PR_RA_INSTANCE,new CMSRAUILoader(uiFramework));
        mContent.put(Constants.PR_OCSP_INSTANCE,new CMSOCSPUILoader(uiFramework));
        //mContent.put("ccm",new CMSCCMUILoader(uiFramework));
    }

    public ISubSystemUILoader getUILoader(String type) throws EAdminException {
        if (!mContent.containsKey(type)) {
            Debug.println("Error Loading Subsystem UI Loader");
            return null;
        }
        return (ISubSystemUILoader) mContent.get(type);
    }
}

//============================================================================

/**
 * Info container for the sub system
 */
class SubSystemInfo {
    String mType;
    String mNickName;
}

/**
 * Interface for the sub system UI loader
 */
interface ISubSystemLocator {
    public SubSystemInfo[] getInstalledSubSystem() throws EAdminException;
}

//XXX DUMMY that just returned with all components
//XXX installed on the srever side
class DefaultSubSystemLocator implements ISubSystemLocator {

    public SubSystemInfo[] getInstalledSubSystem() throws EAdminException {
        SubSystemInfo[] subsystems = new SubSystemInfo[4];
        for (int i=0; i< subsystems.length; i++)
            subsystems[i] = new SubSystemInfo();
        subsystems[0].mType=Constants.PR_CA_INSTANCE;
        subsystems[1].mType=Constants.PR_RA_INSTANCE;
        subsystems[2].mType=Constants.PR_KRA_INSTANCE;
        subsystems[3].mType=Constants.PR_OCSP_INSTANCE;
        //subsystems[3].mType="ccm";
        if (true)
            return subsystems;
        //this should never be called
        throw new EAdminException("DefaultSubSystemLocator - error loading",true);
    }
}

/**
 * This is the one actually used to communicate with the
 * server side and retreive the subsystem actually loaded
 */
class HTTPSSubSystemLocator implements ISubSystemLocator {
    private AdminConnection mConnection;

    public HTTPSSubSystemLocator(AdminConnection conn) {
        mConnection = conn;
    }

    public SubSystemInfo[] getInstalledSubSystem() throws EAdminException {
        NameValuePairs input = getSubSystem();
        Debug.println("getInstalledSubSystem() - "+input.toString());
        SubSystemInfo[] subsystems = new SubSystemInfo[input.size()];
        int i =0;
        for (String entry : input.keySet()) {
            entry = entry.trim();
            String value = input.get(entry);
            subsystems[i] = new SubSystemInfo();
            subsystems[i].mType = value;
            subsystems[i].mNickName = entry;
            i++;
        }
        return subsystems;
    }

    private NameValuePairs getSubSystem() throws EAdminException {
        Debug.println("CMSUIFramework - getSubSystem() - started");
        NameValuePairs response;
        response = mConnection.search(DestDef.DEST_SERVER_ADMIN,
                               ScopeDef.SC_SUBSYSTEM,
                               new NameValuePairs());
        if (response == null) {
            throw new EAdminException("PROTOCOL_ERROR",false);
        }
        Debug.println("CMSUIFramework - getSubSystem() - completed");
        return response;
    }

}

/*
//XXX TBD Read the SubSystem installation information
//XXX from the SIE entry.
class SIESubSystemLocator implements ISubSystemLocator {
    public SubSystemInfo[] getInstalledSubSystem() {
    }
}
*/
