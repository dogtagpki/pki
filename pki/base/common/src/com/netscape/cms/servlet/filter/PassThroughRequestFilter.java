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
// (C) 2009 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.filter;

import javax.servlet.http.*;
import javax.servlet.*;
import com.netscape.certsrv.apps.*;

public class PassThroughRequestFilter implements Filter
{
    /* Create a new PassThroughRequestFilter */
    public PassThroughRequestFilter() {}
    
    public void init( FilterConfig filterConfig )
                throws ServletException
    {
    }
    
    public void doFilter( ServletRequest request, 
                          ServletResponse response,
                          FilterChain chain )
                throws java.io.IOException,
                       ServletException
    {
        // Simply pass-through this request without filtering it . . .
        //
        // NOTE:  This "do-nothing" filter is ONLY provided since
        //        individual servlets can not be "excluded" from within
        //        the <url-pattern></url-pattern> parameters, thus
        //        disallowing the use of a '*' wildcard parameter
        //        on certain filters.
        //
        //        Therefore, since servlets MUST be specified individually
        //        by such filters, this pass-through filter was created to
        //        contain those servlets which would otherwise simply be
        //        "excluded".  Although this could also be accomplished
        //        by merely performing "exclusion by lack of inclusion",
        //        the existance of a pass-through filter allows the
        //        EXPLICIT identification of servlets which MUST NOT
        //        have any filters run against them.
        //

        String filterName = getClass().getName();

        String servlet = null;
        String msg = null;

        if( request instanceof HttpServletRequest ) {
            HttpServletRequest req = ( HttpServletRequest ) request;

            servlet = req.getServletPath();
            msg = "Excluding filtering on servlet called '" + servlet + "'!";
            CMS.debug( filterName + ":  " + msg );
        }

        chain.doFilter( request, response );
    }
    
    public void destroy()
    {
    }
}

