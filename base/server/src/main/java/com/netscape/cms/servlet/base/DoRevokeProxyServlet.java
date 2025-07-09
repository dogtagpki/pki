/* CMS_SDK_LICENSE_TEXT */

package com.netscape.cms.servlet.base;

import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

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
