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
package com.netscape.management.client.security;

/**
 *
 * Client options - individule server should implement this interface
 * then pass this interface to the ClientAuthPanel.
 *
 * This interfaces is used for client auth panel to query server specific
 * encryption settings.
 *
 */
public interface IClientAuthOptions {

    /** Disable client authentication */
    public final static int CLIENT_AUTH_DISABLED = 0;

    /** Enable client authentication */
    public final static int CLIENT_AUTH_ALLOWED  = 1;

    /** Enable and require client authentication */
    public final static int CLIENT_AUTH_REQUIRED = 2;

    /** Default ui setting, display all 3 options */
    public final static int[] DEFAULT_CLIENT_AUTH_UI_OPTIONS = { CLIENT_AUTH_DISABLED, CLIENT_AUTH_ALLOWED, CLIENT_AUTH_REQUIRED };

    /**
     * Invoked when client auth setting is changed
     *
     * @param enabled true if enabled (checkbox is checked), false otherwise
     */
    public abstract void clientAuthSettingChanged(int type);


    /**
     * Call by client auth panel to determain the intial setting
     *
     * @return client setting CLIENT_AUTH_DISABLED | CLIENT_AUTH_ENABLED | CLIENT_AUTH_REQUIRED
     */
    public abstract int getClientAuthSetting();


    /**
     * Call by client auth panel to determain what ui should be display
     *
     * @return array contain a list of ui options to dispaly
     * @see DEFAULT_CLIENT_AUTH_UI_OPTIONS
     */
    public abstract int[] getClientAuthUIOption();

}
