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
package com.netscape.management.client.util;

import java.io.*;
import java.net.*;
import javax.swing.*;

/**
 * Extension of JEditorPane that catches exceptions on invalid URLs and
 * displays them
 *
 * @version 1.0
 * @author rweltman
 **/
public class BrowseHtmlPane extends JEditorPane {
    /**
     * Constructor for blank initial page
     */
    public BrowseHtmlPane() {
        super();
        setEditable( false );
//        setBackground( Color.white );
    }

    /**
     * Constructor to load an initial page
     *
     * @param url The initial HTTP URL to display
     */
    public BrowseHtmlPane( String url ) {
        this();
        setPage( url );
    }

    /**
     * Override JEditorPane.setPage to catch exceptions and print them
     *
     * @param url URL to open
     */
    public void setPage( String url ) {
        try {
            super.setPage( url );
        } catch ( java.io.IOException e ) {
            String text = _resource.getString( "browser-error", "badUrl",
                                               url );
            Debug.println( text );
            setText( text );
        } catch (Throwable t) {
            StringWriter w = new StringWriter();
            t.printStackTrace( new PrintWriter( w ) );
            setText( new String( w.getBuffer() ) );
        }
    }

    /**
     * Override JEditorPane.setPage to catch exceptions and print them
     *
     * @param url URL to open
     */
    public void setPage( URL url ) {
        try {
            super.setPage( url );
        } catch ( java.io.IOException e ) {
            String text = _resource.getString( "browser-error", "badUrl",
                                               url.toString() );
            Debug.println( text );
            setText( text );
        } catch (Throwable t) {
            StringWriter w = new StringWriter();
            t.printStackTrace( new PrintWriter( w ) );
            setText( new String( w.getBuffer() ) );
        }
    }

    private static ResourceSet _resource =
        new ResourceSet("com.netscape.management.client.util.default");
}
