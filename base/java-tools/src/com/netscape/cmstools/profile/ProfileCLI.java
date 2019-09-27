package com.netscape.cmstools.profile;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.cmstools.ca.CACLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileCLI extends CLI {

    public CACLI caCLI;
    public ProfileClient profileClient;

    public ProfileCLI(CACLI caCLI) {
        super("profile", "Profile management commands", caCLI);
        this.caCLI = caCLI;

        addModule(new ProfileFindCLI(this));
        addModule(new ProfileShowCLI(this));
        addModule(new ProfileAddCLI(this));
        addModule(new ProfileModifyCLI(this));
        addModule(new ProfileEditCLI(this));
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

    @Override
    public String getManPage() {
        return "pki-ca-profile";
    }

    public ProfileClient getProfileClient() throws Exception {

        if (profileClient != null) return profileClient;

        PKIClient client = getClient();

        // determine the subsystem
        String subsystem = client.getSubsystem();
        if (subsystem == null) subsystem = "ca";

        // create new profile client
        profileClient = new ProfileClient(client, subsystem);

        return profileClient;
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
            System.out.println("  Name: " + input.getName());
            System.out.println("  Class: " + input.getClassId());
            for (ProfileAttribute attr : input.getAttributes()) {
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

    /** Reads a raw profile from the specified file.
     *
     * @throws PKIException if it doesn't parse as a Properties or
     *         if it doesn't contain the profileId field.
     */
    public static byte[] readRawProfileFromFile(Path path)
            throws PKIException, IOException {
        byte[] s = Files.readAllBytes(path);
        checkConfiguration(s, true /* requireProfileId */, false /* requireDisabled */);
        return s;
    }

    /** Reads a raw profile from the specified file.
     *
     * @throws PKIException if it doesn't parse as a Properties or
     *         if it doesn't contain the profileId field.
     */
    public static byte[] readRawProfileFromFile(String path)
            throws PKIException, IOException {
        return readRawProfileFromFile(Paths.get(path));
    }

    /** Sanity check the profile configuration.
     *
     * We are working with plain byte[] because java.util.Properties
     * has undesirable (i.e. bug-causing) escaping behaviour (it
     * inserts backslashes in places we don't want them).
     *
     * But we do still want to check that the input looks something
     * like a profile configuration.  So we use java.util.Properties
     * to do that.
     */
    public static void checkConfiguration(
            byte[] in,
            boolean requireProfileId,
            boolean requireDisabled)
            throws PKIException {
        Properties p = new Properties();
        try {
            p.load(new ByteArrayInputStream(in));
        } catch (IOException e) {
            throw new PKIException("Failed to parse profile configuration", e);
        }

        if (requireProfileId && p.getProperty("profileId") == null)
            throw new PKIException("Missing profileId property in profile data.");

        String enabled = p.getProperty("enable");
        if (requireDisabled && Boolean.valueOf(enabled)) {
            throw new PKIException("Cannot edit profile. Profile must be disabled.");
        }
    }

    public static void saveEnrollmentTemplateToFile(String filename, CertEnrollmentRequest request)
            throws JAXBException, FileNotFoundException {
        JAXBContext context = JAXBContext.newInstance(CertEnrollmentRequest.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        FileOutputStream stream = new FileOutputStream(filename);
        marshaller.marshal(request, stream);

        MainCLI.printMessage("Saved enrollment template for " + request.getProfileId() + " to " + filename);
    }

    public static void printEnrollmentTemplate(CertEnrollmentRequest request) {
        System.out.println("  Profile ID: " +  request.getProfileId());
        System.out.println("  Renewal: " + request.isRenewal());

        for (ProfileInput input: request.getInputs()) {
            System.out.println();
            System.out.println("  Name: " + input.getName());
            System.out.println("  Class: " + input.getClassId());
            for (ProfileAttribute attr : input.getAttributes()) {
                System.out.println();
                System.out.println("    Attribute Name: " + attr.getName());
                System.out.println("    Attribute Description: " +
                    attr.getDescriptor().getDescription(Locale.getDefault()));
                System.out.println("    Attribute Syntax: " +
                    attr.getDescriptor().getSyntax());
            }
        }

        for (ProfileOutput output: request.getOutputs()) {
            System.out.println();
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
}
