package com.netscape.cmstools.authority;

import java.math.BigInteger;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.ca.CACLI;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityCLI extends CLI {

    public CACLI caCLI;
    public AuthorityClient authorityClient;

    public AuthorityCLI(CACLI caCLI) {
        super("authority", "CA management commands", caCLI);
        this.caCLI = caCLI;

        addModule(new AuthorityFindCLI(this));
        addModule(new AuthorityShowCLI(this));
        addModule(new AuthorityCreateCLI(this));
        addModule(new AuthorityDisableCLI(this));
        addModule(new AuthorityEnableCLI(this));
        addModule(new AuthorityRemoveCLI(this));
        addModule(new AuthorityKeyExportCLI(this));
    }

    @Override
    public String getFullName() {
        // do not include MainCLI's name
        return parent instanceof MainCLI ? name : parent.getFullName() + "-" + name;
    }

    public AuthorityClient getAuthorityClient() throws Exception {

        if (authorityClient != null) return authorityClient;

        PKIClient client = getClient();
        authorityClient = new AuthorityClient(client, "ca");

        return authorityClient;
    }

    protected static void printAuthorityData(AuthorityData data) {
        Boolean isHostAuthority = data.getIsHostAuthority();
        if (isHostAuthority != null && isHostAuthority)
            System.out.println("  Host authority: true");
        System.out.println("  Authority DN:   " + data.getDN());
        System.out.println("  ID:             " + data.getID());

        String parentAID = data.getParentID();
        if (parentAID != null)
            System.out.println("  Parent ID:      " + parentAID);

        String issuerDN = data.getIssuerDN();
        if (issuerDN != null)
            System.out.println("  Issuer DN:      " + issuerDN);

        BigInteger serial = data.getSerial();
        if (serial != null) {
            CertId certID = new CertId(serial);
            System.out.println("  Serial no:      " + certID.toHexString());
        }

        System.out.println("  Enabled:        " + data.getEnabled());
        System.out.println("  Ready to sign:  " + data.getReady());
        String desc = data.getDescription();
        if (desc != null)
            System.out.println("  Description:    " + desc);
    }

}
