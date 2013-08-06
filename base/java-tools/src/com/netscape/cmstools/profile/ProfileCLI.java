package com.netscape.cmstools.profile;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Locale;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileCLI extends CLI {

    public ProfileClient profileClient;

    public ProfileCLI(CLI parent) {
        super("profile", "Profile management commands", parent);

        addModule(new ProfileFindCLI(this));
        addModule(new ProfileShowCLI(this));
        addModule(new ProfileAddCLI(this));
        addModule(new ProfileModifyCLI(this));
        addModule(new ProfileRemoveCLI(this));
        addModule(new ProfileEnableCLI(this));
        addModule(new ProfileDisableCLI(this));
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
        profileClient = new ProfileClient(client);

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printProfileDataInfo(ProfileDataInfo info) {
        System.out.println("  Profile ID: " + info.getProfileId());
        if (verbose) {
            System.out.println("  URL: " + info.getProfileURL());
        }
        System.out.println("  Name: " + info.getProfileName());
        System.out.println("  Description: " + info.getProfileDescription());
    }

    public static void printProfile(ProfileData data, URI baseUri) {
        System.out.println("  Profile ID: " + data.getId());
        if (verbose) {
            System.out.println("  URL: " + data.getLink().getHref().toString());
        }
        System.out.println("  Name: " + data.getName());
        System.out.println("  Description: " + data.getDescription());

        for (ProfileInput input: data.getInputs()) {
            System.out.println();
            System.out.println("  Input ID: " + input.getId());
            System.out.println("  Name: " + input.getName());
            System.out.println("  Class: " + input.getClassId());
            for (ProfileAttribute attr: input.getAttrs()) {
                System.out.println();
                System.out.println("    Attribute Name: " + attr.getName());
                System.out.println("    Attribute Description: " +
                    attr.getDescriptor().getDescription(Locale.getDefault()));
                System.out.println("    Attribute Syntax: " +
                    attr.getDescriptor().getSyntax());
            }
        }

        for (ProfileOutput output: data.getOutputs()) {
            System.out.println();
            System.out.println("  Output ID: " + output.getId());
            System.out.println("  Name: " + output.getName());
            System.out.println("  Class: " + output.getClassId());
            for (ProfileAttribute attr: output.getAttrs()) {
                System.out.println();
                System.out.println("    Attribute Name: " + attr.getName());
                System.out.println("    Attribute Description: " +
                    attr.getDescriptor().getDescription(Locale.getDefault()));
                System.out.println("    Attribute Syntax: " +
                    attr.getDescriptor().getSyntax());
            }
        }
    }

    public static void saveProfileToFile(String filename, ProfileData data)
            throws JAXBException, FileNotFoundException {
        JAXBContext context = JAXBContext.newInstance(ProfileData.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        FileOutputStream stream = new FileOutputStream(filename);
        marshaller.marshal(data, stream);

        MainCLI.printMessage("Saved profile " + data.getId() + " to " + filename);
    }

    public static ProfileData readProfileFromFile(String filename)
            throws JAXBException, FileNotFoundException {
        ProfileData data = null;
        JAXBContext context = JAXBContext.newInstance(ProfileData.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        FileInputStream fis = new FileInputStream(filename);
        data = (ProfileData) unmarshaller.unmarshal(fis);
        return data;
    }
}
