/* CMS_SDK_LICENSE_TEXT */

package com.netscape.cms.servlet.base;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;

/**
 * This is a servlet that proxies request to another servlet.
 *
 * SERVLET REDIRECTION
 * Specify the URL of a servlet to forward the request to
 * destServlet: /ee/ca/newservlet
 *
 * PARAMETER MAPPING
 * In the servlet configuration (as an init-param in web.xml) you
 * can optionally specify a value for the parameter 'parameterMap'
 * which contains a list of HTTP parameters which should be
 * translated to new names.
 *
 * parameterMap: name1->newname1,name2->newname2
 *
 * Optionally, names can be set to static values:
 *
 * parameterMap: name1->name2=value
 *
 * Examples:
 * Consider the following HTTP input parameters:
 * vehicle:car make:ford model:explorer
 *
 * The following config strings will have this effect:
 * parameterMap: make->manufacturer,model->name=expedition,->suv=true
 * output: vehicle:car manufactuer:ford model:expedition suv:true
 *
 * @version $Revision$, $Date$
 */
public class ProxyServlet extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = -2535349161521094539L;
    private String mDest = null;
    private String mDestContext = null;
    private String mSrcContext = null;
    private String mAppendPathInfo = null;
    private Vector<String> mMatchStrings = new Vector<String>();
    private String mDestServletOnNoMatch = null;
    private String mAppendPathInfoOnNoMatch = null;
    private Map<String, String> mParamMap = new HashMap<String, String>();
    private Map<String, String[]> mParamValue = new HashMap<String, String[]>();

    public ProxyServlet() {
    }

    private void parseParamTable(String s) {
        if (s == null)
            return;

        String[] params = s.split(",");
        for (int i = 0; i < params.length; i++) {
            String p = params[i];
            if (p != null) {
                String[] paramNames = p.split("->");
                if (paramNames.length != 2) {
                }
                String from = paramNames[0];
                String to = paramNames[1];
                if (from != null && to != null) {
                    String[] splitTo = to.split("=");
                    String toName = splitTo[0];
                    if (from.length() > 0) {
                        mParamMap.put(from, toName);
                    }
                    if (splitTo.length == 2) {
                        String toValue = splitTo[1];
                        String toValues[] = new String[1];
                        toValues[0] = toValue;
                        mParamValue.put(toName, toValues);
                    }
                }
            }
        }
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        String mMatchStrs = sc.getInitParameter("matchURIStrings");
        if (mMatchStrs != null && (!mMatchStrs.equals(""))) {
            StringTokenizer st = new StringTokenizer(mMatchStrs, ",");
            while (st.hasMoreTokens()) {
                mMatchStrings.addElement(st.nextToken());
            }
        }
        mDestServletOnNoMatch = sc.getInitParameter("destServletOnNoMatch");
        mDestContext = sc.getInitParameter("destContext");
        mDest = sc.getInitParameter("destServlet");
        mSrcContext = sc.getInitParameter("srcContext");
        mAppendPathInfo = sc.getInitParameter("appendPathInfo");
        mAppendPathInfoOnNoMatch = sc.getInitParameter("appendPathInfoOnNoMatch");
        String map = sc.getInitParameter("parameterMap");
        if (map != null) {
            parseParamTable(map);
        }
    }

    public void service(HttpServletRequest req, HttpServletResponse res) throws
            IOException, ServletException {
        RequestDispatcher dispatcher = null;
        String dest = mDest;
        String uri = req.getRequestURI();

        // check if match strings are specified. If it is, we need
        // to deal with the alternate dest
        if (mMatchStrings.size() != 0) {
            boolean matched = false;
            for (int i = 0; i < mMatchStrings.size(); i++) {
                String t = mMatchStrings.elementAt(i);
                if (uri.indexOf(t) != -1) {
                    matched = true;
                }
            }
            if (!matched) {
                dest = mDestServletOnNoMatch;
                // append Path info for OCSP request in Get method
                if (mAppendPathInfoOnNoMatch != null &&
                        !mAppendPathInfoOnNoMatch.equals("")) {
                    dest = dest + uri.replace(mAppendPathInfoOnNoMatch, "");
                }
            }
        }
        if (dest == null || dest.equals("")) {
            // mapping everything
            dest = uri;
            dest = dest.replaceFirst(mSrcContext, "");
        }
        if (mAppendPathInfo != null && !mAppendPathInfo.equals("")) {
            dest = dest + uri.replace(mAppendPathInfo, "");
        }
        if (mDestContext != null && !mDestContext.equals("")) {
            dispatcher = getServletContext().getContext(mDestContext).getRequestDispatcher(dest);
        } else {
            dispatcher = req.getRequestDispatcher(dest);
        }

        // If a parameter map was specified
        if (mParamMap != null && !mParamMap.isEmpty()) {
            // Make a new wrapper with the new parameters
            ProxyWrapper r = new ProxyWrapper(req);
            r.setParameterMapAndValue(mParamMap, mParamValue);
            req = r;
        }

        dispatcher.forward(req, res);
    }
}

class ProxyWrapper extends HttpServletRequestWrapper {
    private Map<String, String> mMap = null;
    private Map<String, String[]> mValueMap = null;

    public ProxyWrapper(HttpServletRequest req) {
        super(req);
    }

    public void setParameterMapAndValue(Map<String, String> m, Map<String, String[]> v) {
        if (m != null)
            mMap = m;
        if (v != null)
            mValueMap = v;
    }

    public Map<String, String[]> getParameterMap() {
        try {
            // If we haven't specified any parameter mapping, just
            // use the regular implementation
            if (mMap == null)
                return super.getParameterMap();
            else {
                // Make a new Map for us to put stuff in
                Map<String, String[]> n = new HashMap<String, String[]>();
                // get the HTTP parameters the user supplied.
                Map<String, String[]> m = super.getParameterMap();
                Set<Map.Entry<String, String[]>> s = m.entrySet();
                Iterator<Map.Entry<String, String[]>> i = s.iterator();
                while (i.hasNext()) {
                    Map.Entry<String, String[]> me = i.next();
                    String name = me.getKey();
                    String[] values = me.getValue();
                    String newname = null;
                    if (name != null) {
                        newname = mMap.get(name);
                    }

                    // No mapping specified, just use existing name/value
                    if (newname == null || mValueMap == null) {
                        n.put(name, values);
                    } else { // new name specified
                        Object o = mValueMap.get(newname);
                        // check if new (static) value specified
                        if (o == null) {
                            n.put(newname, values);
                        } else {
                            String newvalues[] = mValueMap.get(newname);
                            n.put(newname, newvalues);
                        }
                    }
                }
                // Now, deal with static values set in the config
                // which weren't set in the HTTP request
                Set<Map.Entry<String, String[]>> s2 = mValueMap.entrySet();
                Iterator<Map.Entry<String, String[]>> i2 = s2.iterator();
                // Cycle through all the static values
                while (i2.hasNext()) {
                    Map.Entry<String, String[]> me2 = i2.next();
                    String name2 = me2.getKey();
                    if (n.get(name2) == null) {
                        String[] values2 = me2.getValue();
                        // If the parameter is not set in the map
                        // Set it now
                        n.put(name2, values2);
                    }
                }

                return n;
            }
        } catch (NullPointerException npe) {
            CMS.debug(npe);
            return null;
        }
    }
}
