/* CMS_SDK_LICENSE_TEXT */

package com.netscape.cms.servlet.base;

import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

@WebServlet(
        name = "caProxyBulkIssuance",
        urlPatterns = "/agent/bulkissuance",
        initParams = {
                @WebInitParam(name="destServlet", value="/agent/ca/bulkissuance")
        }
)
public class BulkIssuanceProxyServlet extends ProxyServlet {
    private static final long serialVersionUID = 1L;
}
