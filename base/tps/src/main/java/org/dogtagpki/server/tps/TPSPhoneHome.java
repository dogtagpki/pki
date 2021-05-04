package org.dogtagpki.server.tps;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.tps.main.TPSBuffer;

public class TPSPhoneHome extends HttpServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSPhoneHome.class);
    private static final long serialVersionUID = 1864386666927370987L;
    private static String phoneHomeName = "phoneHome.xml";

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

            String confPath = getConfigPath();

            if(confPath == null) {
                throw new IOException("TPSPhoneHome.rederPhoneHome: Can not deteriming path to phone home data!");
            }

            confPath += File.separator + phoneHomeName;

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

        String path = null;
        String context = getServletContext().getContextPath();

        // get subsystem name by removing the / prefix from the context
        String subsystem = context.startsWith("/") ? context.substring(1) : context;

        // catalina.base points to instance dir
        String instanceDir = null;

        try {

            instanceDir = System.getProperty("catalina.base");

        } catch (Exception e) {
            logger.warn("TPSPhoneHome.getConfigPath: System.getProperty: " + e.getMessage(), e);
            return null;
        }

        logger.debug("TPSPhoneHome.getConfigPath: instanceDir: " + instanceDir);

        //Finish off path of conf directory
        path = instanceDir + File.separator + "conf" + File.separator +
                subsystem + File.separator;

        logger.debug("TPSPhoneHome.getConfigPath: returning: " + path);

        return path;

    }

}
