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
package com.netscape.management.client;

import java.awt.Cursor;
import java.awt.Image;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.JFrame;

import com.netscape.management.client.preferences.IPreferencesTab;
import com.netscape.management.client.util.About;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.UtilConsoleGlobals;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;

/**
  * An implemenation of the IFrameworkInitializer interface that
  * specifies properties of a Console window.
  *
  * @see IFramework
  * @see IFrameworkInitializer
  */
public abstract class FrameworkInitializer implements IFrameworkInitializer {
    ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");
    protected Vector pageList = new Vector();
    protected Vector tabList = new Vector();
    protected String frameTitle = null;
    protected Image minimizedImage = null;
    protected Image bannerImage = null;
    protected String bannerText = null;
    protected About about = null;
    protected AboutDialog aboutDialog = null;
    private UIPermissions uiPermissions = null;

    /**
      * Returns new FrameworkInitializer.
      */
    public FrameworkInitializer() {
    }

    /**
       * Adds a page.
       */
    public void addPage(IPage page) {
        pageList.addElement(page);
    }

    /**
       * Removes a page.
       */
    public void removePage(IPage page) {
        pageList.removeElement(page);
    }

    /**
       * Returns total number of pages.
     * Called by IFramework.
       */
    public int getPageCount() {
        return pageList.size();
    }

    /**
       * Returns page at the given index.
     * Called by IFramework.
       */
    public IPage getPageAt(int index) {
        IPage page;
        page = (IPage)pageList.elementAt(index);
        return page;
    }

    /**
       * Returns title for framework window, displayed in title bar.
     * Called by IFramework.
       */
    public String getFrameTitle() {
        return frameTitle;
    }

    /**
       * Returns image for framework window title bar (Windows only) as well as when minimized.
     * Use a 32x32 icon.  The image will be resized to smaller resolutions as needed.
     * Use RemoteImage("filename").getImage() to get an Image.
     * Called by IFramework.
       */
    public Image getMinimizedImage() {
        return minimizedImage;
    }

    /**
       * Sets text for window title bar.
     * Called by consumer of this FrameworkInitializer.
       */
    public void setFrameTitle(String newTitle) {
        frameTitle = newTitle;
    }

    /**
       * Sets text for window title bar.
     * Called by consumer of this FrameworkInitializer.
       */
    public void setFrameTitle(LDAPConnection ldc, String serverInstanceDN) {
        if (ldc == null || ldc.isConnected() == false) {
            return;
        }
        try {
            LDAPEntry entry = ldc.read(serverInstanceDN);
            String locale = LDAPUtil.getLDAPAttributeLocale();
            LDAPAttribute attr =
                    entry.getAttribute("serverproductname", locale);
            if (attr == null) {
                attr = entry.getAttribute("cn", locale);
                if (attr != null) {
                    frameTitle = LDAPUtil.flatting(attr);
                }
            } else {
                frameTitle = LDAPUtil.flatting(attr);
            }
        } catch (LDAPException e) {
            Debug.println(0, "FrameworkInitializer.setFrameTitle: " + e);
        }
    }

    /**
       * Returns image for framework window title bar (Windows only) as well as when minimized.
     * Use a 32x32 icon.  The image will be resized to smaller resolutions as needed.
     * Use RemoteImage("filename").getImage() to get an Image.
       */
    public void setMinimizedImage(Image image) {
        minimizedImage = image;
    }

    /**
       * Sets banner image, displayed between the framework menu bar and tab pane.
     * Called by IFramework.
       */
    public void setBannerImage(Image image) {
        bannerImage = image;
    }

    /**
       * Returns banner image.  Displayed between the framework
     * menu bar and tab pane.
     * Called by IFramework.
       */
    public Image getBannerImage() {
        return bannerImage;
    }

    /**
       * Sets banner text.  Displayed between the framework
     * menu bar and tab pane.
     * Called by IFramework.
       */
    public void setBannerText(String text) {
        bannerText = text;
    }

    /**
       * Sets text for window title bar.
     * Called by consumer of this FrameworkInitializer.
       */
    public void setBannerText(LDAPConnection ldc, String serverInstanceDN) {
        if (ldc == null || ldc.isConnected() == false) {
            return;
        }
        try {
            LDAPEntry entry = ldc.read(serverInstanceDN);
            String locale = LDAPUtil.getLDAPAttributeLocale();
            LDAPAttribute attr =
                    entry.getAttribute("serverproductname", locale);
            if (attr == null) {
                attr = entry.getAttribute("cn", locale);
                if (attr != null) {
                    bannerText = LDAPUtil.flatting(attr);
                }
            } else {
                bannerText = LDAPUtil.flatting(attr);
            }
        } catch (LDAPException e) {
            Debug.println(0, "FrameworkInitializer.setFrameTitle: " + e);
        }
    }

    /**
       * Returns banner text.  Displayed between the framework
     * menu bar and tab pane.
     * Called by IFramework.
       */
    public String getBannerText() {
        if (bannerText == null) {
            return frameTitle;
        }
        return bannerText;
    }

    public void setUIPermissions(UIPermissions uip)
    {
        uiPermissions = uip;
        addPreferencesTab(new UIPermissionsPreferencesTab());
    }

    public UIPermissions getUIPermissions()
    {
        return uiPermissions;
    }

    public void addPreferencesTab(IPreferencesTab tab)
    {
        tabList.addElement(tab);
    }

    public void removePreferencesTab(IPreferencesTab tab)
    {
        tabList.removeElement(tab);
    }

    public IPreferencesTab getPreferencesTab(int index)
    {
        return (IPreferencesTab)tabList.elementAt(index);
    }

    public int getPreferencesTabCount()
    {
        return tabList.size();
    }

    /**
     * Returns resource boundle contain information for about dialog
     *
     * @deprecated overload aboutInvoked() instead
     */
    @Deprecated
    public ResourceSet getAboutDialogResourceBoundle() {
        return null;
    }

    /**
       * pop up a default about dialog
     *
     *
       */
    public void aboutInvoked(JFrame parent) {
        try {
            UtilConsoleGlobals.getActivatedFrame().setCursor(
                    new Cursor(Cursor.WAIT_CURSOR));
            if (aboutDialog == null) {
                ResourceSet aboutDialogResource = new ResourceSet("com.netscape.management.client.defaultLicense");
                ResourceSet themeResource = new ResourceSet("com.netscape.management.client.theme.theme");
                aboutDialog = new AboutDialog(parent,
                        themeResource.getString("defaultAbout",
                        "dialogTitle"));
                aboutDialog.setProduct( new RemoteImage(
                        themeResource.getString("defaultAbout",
                        "productLogo")),
                        aboutDialogResource.getString("defaultAbout",
                        "productCopyright"),
                        themeResource.getString("defaultAbout",
                        "productLicense"));

                StringTokenizer st = new StringTokenizer(
                        aboutDialogResource.getString("defaultAbout",
                        "vendorsList"), ",", false);
                while (st.hasMoreTokens()) {

                    String token = st.nextToken();
                    RemoteImage logo = null;
                    try {
                        logo = new RemoteImage(
                                aboutDialogResource.getString("defaultAbout",
                                "vendor-"+token + "-logo"));
                    } catch (Exception e) {}
                    aboutDialog.addVendor(logo,
                            aboutDialogResource.getString("defaultAbout",
                            "vendor-"+token + "-license"));
                }
            }
            aboutDialog.show();
            UtilConsoleGlobals.getActivatedFrame().setCursor(
                    new Cursor(Cursor.DEFAULT_CURSOR));
        } catch (Exception e) {
            Debug.println("FrameworkInitializer:"+e);
        }
    }
}
