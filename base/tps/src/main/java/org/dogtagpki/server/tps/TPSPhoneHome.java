package org.dogtagpki.server.tps;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.tps.main.TPSBuffer;

import com.netscape.cmscore.apps.CMS;

@WebServlet(
        name = "phoneHome",
        urlPatterns = "/phoneHome"
)
public class TPSPhoneHome extends HttpServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSPhoneHome.class);
    private static final long serialVersionUID = 1864386666927370987L;
    private static String phoneHomeName = "phoneHome.xml";

    @Override
    public void service(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        //Simply return xml file to the client
        //In the future we could get this info from elsewhere such as LDAP

        logger.debug("TPSPhoneHome entering.");

        renderPhoneHome(request, response);
    }

    private void renderPhoneHome(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {
        ServletOutputStream stream = null;
        BufferedInputStream buf = null;
        FileInputStream input = null;
        logger.debug("TPSPhoneHome.renderPhoneHome entering.");

        try {

            stream = response.getOutputStream();
            response.setContentType("application/xml");

            String confPath = getConfigPath() + File.separator + phoneHomeName;
            logger.debug("TPSPhoneHome.renderPhoneHome: confPath: " + confPath);

            input = new FileInputStream(confPath);
            // InputStream input = ctx.getResourceAsStream(phoneHomeName);
            buf = new BufferedInputStream(input);

            int readBytes = 0;
            TPSBuffer readData = new TPSBuffer();
            while ((readBytes = buf.read()) != -1) {
                stream.write(readBytes);
                readData.add((byte) readBytes);
            }

            logger.debug("TPSPhoneHome.renderPhoneHome: data: " + readData.toHexString());

        } catch (IOException e) {
            logger.error("TPSPhoneHome.renderPhoneHome:  " + e.getMessage(), e);
            throw new ServletException("TPSPhoneHome.renderPhoneHome: Error encountered:  " + e);
        } finally {
            if (stream != null)
                stream.close();
            if (buf != null)
                buf.close();
            if (input != null)
                input.close();
        }

    }

    private String getConfigPath() {

        logger.debug("TPSPhoneHome.getConfigPath: entering.");

        String context = getServletContext().getContextPath();

        // get subsystem name by removing the / prefix from the context
        String subsystem = context.startsWith("/") ? context.substring(1) : context;

        String instanceDir = CMS.getInstanceDir();
        logger.debug("TPSPhoneHome.getConfigPath: instanceDir: " + instanceDir);

        //Finish off path of conf directory
        String path = instanceDir + File.separator + "conf" + File.separator + subsystem + File.separator;
        logger.debug("TPSPhoneHome.getConfigPath: returning: " + path);

        return path;

    }

}
