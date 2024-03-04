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

import java.awt.Image;

import javax.swing.JFrame;

import com.netscape.management.client.util.ResourceSet;

/**
  * An interface to initialize properties of a Framework object
  * (a Console window)
  *
  * @see FrameworkInitializer
  * @see Framework
  */
public interface IFrameworkInitializer {
    /**
       * Returns total number of IPage objects referenced.
       *
     * @return a count of IPage objects
     * @see getPageAt
       */
    public abstract int getPageCount();

    /**
      * Returns an IPage object a specified index.  The Framework
      * calls this method up to a maximum of getPageCount()
      * times to retrieve each IPage.
      *
    * @return an IPage object at the specified index
      */
    public abstract IPage getPageAt(int index);

    /**
      * Returns title for framework window, displayed in title bar.
    * Called by IFramework.
      */
    public abstract String getFrameTitle();

    /**
      * Returns image for framework window title bar (Windows only) as well as when minimized.
    * Use a 32x32 icon.  The image will be resized to smaller resolutions as needed.
    * Use RemoteImage("filename").getImage() to get an Image.
    * Called by IFramework.
      */
    public abstract Image getMinimizedImage();

    /**
      * Returns banner image.  Displayed between the framework
    * menu bar and tab pane.
    * Called by IFramework.
      */
    public abstract Image getBannerImage();

    /**
      * Returns banner text.  Displayed between the framework
    * menu bar and tab pane.
    * Called by IFramework.
      */
    public abstract String getBannerText();

    /**
      * Returns resource boundle contain information for about dialog
    *
    * @deprecated substituted by aboutInvoked()
      */
    @Deprecated
    public abstract ResourceSet getAboutDialogResourceBoundle();

    /**
      * pop up a default about dialog
    *
    *
      */
    public abstract void aboutInvoked(JFrame parent);
}
