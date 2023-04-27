/* CMS_SDK_LICENSE_TEXT */

package com.netscape.cms.servlet.base;

import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;

@WebServlet(
        name = "caProxyDoRevoke",
        urlPatterns = "/doRevoke",
        initParams = {
                @WebInitParam(name="destServlet", value="/agent/ca/doRevoke")
        }
)
public class DoRevokeProxyServlet extends ProxyServlet {
    private static final long serialVersionUID = 1L;
}
