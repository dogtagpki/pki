/* CMS_SDK_LICENSE_TEXT */

package com.netscape.cms.servlet.base;

import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

@WebServlet(
        name = "caProxyProfileSubmit",
        urlPatterns = "/profileSubmit",
        initParams = {
                @WebInitParam(name="destServlet", value="/ee/ca/profileSubmit")
        }
)
public class ProfileSubmitProxyServlet extends ProxyServlet {
    private static final long serialVersionUID = 1L;
}
