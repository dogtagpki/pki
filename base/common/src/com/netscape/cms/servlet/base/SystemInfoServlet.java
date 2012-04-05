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
package com.netscape.cms.servlet.base;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;

/**
 * Displays detailed information about java VM internals, including
 * current JVM memory usage, and detailed information about each
 * thread.
 * <p>
 * Also allows user to trigger a new garbage collection
 *
 * @version $Revision$, $Date$
 */
public class SystemInfoServlet extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = -438134935001530607L;

    public SystemInfoServlet() {
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
    }

    /**
     * service the request, returning HTML to the client.
     * This method has different behaviour depending on the
     * value of the 'op' HTTP parameter.
     * <UL>
     * <LI>op = <i>undefined</i> - display a menu with links to the other functionality of this servlet
     * <li>op = gc - tell the JVM that we want to do a garbage collection and to run finalizers (@see
     * java.lang.Runtime.getRuntime#gc() )
     * <li>op = general - display information about memory, and other JVM informatino
     * <li>op = thread - display details about each thread.
     * </UL>
     *
     * @see javax.servlet.http.HttpServlet#service(HttpServletRequest, HttpServletResponse)
     */
    public void service(HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {
        String op = request.getParameter("op");

        response.setContentType("text/html");
        if (op == null) {
            mainMenu(request, response);
        } else if (op.equals("gc")) {
            gc(request, response);
        } else if (op.equals("general")) {
            general(request, response);
        } else if (op.equals("thread")) {
            thread(request, response);
        }
    }

    private void mainMenu(HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {
        response.getWriter().println("<HTML>");
        response.getWriter().println("<H1>");
        response.getWriter().println("<a href=" + request.getServletPath() + ">");
        response.getWriter().println("Main");
        response.getWriter().println("</a>");
        response.getWriter().println("</H1>");
        response.getWriter().println("<p>");
        response.getWriter().println("<table>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("<li>");
        response.getWriter().println("<a href=" + request.getServletPath() + "?op=general>");
        response.getWriter().println("General");
        response.getWriter().println("</a>");
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("<li>");
        response.getWriter().println("<a href=" + request.getServletPath() + "?op=gc>");
        response.getWriter().println("Garbage Collection");
        response.getWriter().println("</a>");
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("<li>");
        response.getWriter().println("<a href=" + request.getServletPath() + "?op=thread>");
        response.getWriter().println("Thread Listing");
        response.getWriter().println("</a>");
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("</table>");
        response.getWriter().println("</HTML>");
    }

    private void gc(HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {
        java.lang.Runtime.getRuntime().gc();
        java.lang.Runtime.getRuntime().runFinalization();
        response.getWriter().println("<HTML>");
        response.getWriter().println("<H1>");
        response.getWriter().println("<a href=" + request.getServletPath() + ">");
        response.getWriter().println("Main");
        response.getWriter().println("</a>");
        response.getWriter().println(" : ");
        response.getWriter().println("Garbage Collection");
        response.getWriter().println("</H1>");
        response.getWriter().println("<p>");
        response.getWriter().println("The garbage collector has been executed.");
        response.getWriter().println("</HTML>");
    }

    private void general(HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {
        response.getWriter().println("<HTML>");
        response.getWriter().println("<H1>");
        response.getWriter().println("<a href=" + request.getServletPath() + ">");
        response.getWriter().println("Main");
        response.getWriter().println("</a>");
        response.getWriter().println(" : ");
        response.getWriter().println("General");
        response.getWriter().println("</H1>");
        response.getWriter().println("<p>");
        response.getWriter().println("<table>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("Server Started Time:");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println(new Date(CMS.getStartupTime()));
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("Current Time:");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println(new Date());
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("Available Processors:");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println(Runtime.getRuntime().availableProcessors());
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("Active Threads:");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println(Thread.activeCount());
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("Max Memory (in Bytes):");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println(Runtime.getRuntime().maxMemory());
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("Total Memory (in Bytes):");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println(Runtime.getRuntime().totalMemory());
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("Free Memory (in Bytes):");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println(Runtime.getRuntime().freeMemory());
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("Free Memory / Total Memory:");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println(
                (Runtime.getRuntime().freeMemory() * 100) / Runtime.getRuntime().totalMemory() + "%");
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        response.getWriter().println("</table>");
        response.getWriter().println("</HTML>");
    }

    private void thread(HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {
        response.getWriter().println("</table>");
        response.getWriter().println("<HTML>");
        response.getWriter().println("<H1>");
        response.getWriter().println("<a href=" + request.getServletPath() + ">");
        response.getWriter().println("Main");
        response.getWriter().println("</a>");
        response.getWriter().println(" : ");
        response.getWriter().println("Thread Listing");
        response.getWriter().println("</H1>");
        response.getWriter().println("<p>");
        response.getWriter().println("<table width=100% border=1>");
        response.getWriter().println("<tr>");
        response.getWriter().println("<td>");
        response.getWriter().println("<b>");
        response.getWriter().println("#");
        response.getWriter().println("</b>");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println("<b>");
        response.getWriter().println("Name");
        response.getWriter().println("</b>");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println("<b>");
        response.getWriter().println("Priority");
        response.getWriter().println("</b>");
        response.getWriter().println("</td>");
        response.getWriter().println("<td>");
        response.getWriter().println("<b>");
        response.getWriter().println("isDaemon");
        response.getWriter().println("</b>");
        response.getWriter().println("</td>");
        response.getWriter().println("</tr>");
        int active = Thread.activeCount();
        Thread threads[] = new Thread[active];
        int c = Thread.enumerate(threads);

        for (int i = 0; i < c; i++) {
            response.getWriter().println("<tr>");
            response.getWriter().println("<td>");
            response.getWriter().println(i);
            response.getWriter().println("</td>");
            response.getWriter().println("<td>");
            response.getWriter().println(threads[i].getName());
            response.getWriter().println("</td>");
            response.getWriter().println("<td>");
            response.getWriter().println(threads[i].getPriority());
            response.getWriter().println("</td>");
            response.getWriter().println("<td>");
            if (threads[i].isDaemon()) {
                response.getWriter().println("true");
            } else {
                response.getWriter().println("false");
            }
            response.getWriter().println("</td>");
            response.getWriter().println("</tr>");
        }
        response.getWriter().println("</table>");
        response.getWriter().println("</HTML>");
    }
}
