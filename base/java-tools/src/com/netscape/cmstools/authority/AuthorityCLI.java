package com.netscape.cmstools.authority;

import java.math.BigInteger;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityCLI extends CLI {

    public AuthorityClient authorityClient;

    public AuthorityCLI(CLI parent) {
        super("authority", "CA management commands", parent);

        addModule(new AuthorityFindCLI(this));
        addModule(new AuthorityShowCLI(this));
        addModule(new AuthorityCreateCLI(this));
        addModule(new AuthorityDisableCLI(this));
        addModule(new AuthorityEnableCLI(this));
        addModule(new AuthorityRemoveCLI(this));
        addModule(new AuthorityKeyExportCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public void execute(String[] args) throws Exception {
        client = parent.getClient();
        authorityClient = new AuthorityClient(client, "ca");
        super.execute(args);
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
        if (serial != null)
            System.out.println("  Serial no:      " + serial);

        System.out.println("  Enabled:        " + data.getEnabled());
        System.out.println("  Ready to sign:  " + data.getReady());
        String desc = data.getDescription();
        if (desc != null)
            System.out.println("  Description:    " + desc);
    }

}
