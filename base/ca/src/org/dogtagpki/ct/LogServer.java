package org.dogtagpki.ct;

import java.net.URL;

import com.netscape.certsrv.base.BadRequestException;

public class LogServer {

    private int id;
    private String publicKey;
    private int version;
    private boolean enabled;
    private URL url;

    public URL getUrl() {
        return url;
    }

    public void setUrl(URL url) {
        this.url = url;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }
    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        if(version == 1) {
            this.version = version;
        } else if (version == 2) {
            throw new BadRequestException("Version 2 not supported");
        } else {
            throw new BadRequestException("Only CT Version 1 is supported");
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
