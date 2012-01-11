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
package com.netscape.cms.servlet.wizard;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.property.PropertySet;

public interface IWizardPanel {

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
                 throws ServletException;

    public void init(WizardServlet servlet, ServletConfig config,
                     int panelno, String id) throws ServletException;

    public String getName();

    public int getPanelNo();

    public void setId(String id);

    public String getId();

    public PropertySet getUsage();

    /**
     * Should we skip this panel to the next one?
     */
    public boolean shouldSkip();

    /**
     * Cleans up panel so that isPanelDone returns false
     */
    public void cleanUp() throws IOException;

    /**
     * Is this panel done
     */
    public boolean isPanelDone();

    /**
     * Show "Apply" button on frame?
     */
    public boolean showApplyButton();

    /**
     * Is this a subPanel?
     */
    public boolean isSubPanel();

    public boolean isLoopbackPanel();

    /**
     * has subPanels?
     */
    public boolean hasSubPanel();

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context);

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context) throws IOException;

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
                          HttpServletResponse response,
                          Context context) throws IOException;

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context);
}
