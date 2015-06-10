package com.netscape.cmstools.authority;

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
            System.out.println("  Parent ID:      " + data.getParentID());
        System.out.println("  Enabled:        " + data.getEnabled());
        String desc = data.getDescription();
        if (desc != null)
            System.out.println("  Description:    " + desc);
    }

}
