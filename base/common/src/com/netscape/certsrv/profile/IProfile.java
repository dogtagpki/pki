// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.profile;

import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;

/**
 * This interface represents a profile. A profile contains
 * a list of input policies, default policies, constraint
 * policies and output policies.
 * <p>
 *
 * The input policy is for building the enrollment page.
 * <p>
 *
 * The default policy is for populating user-supplied and system-supplied values into the request.
 * <p>
 *
 * The constraint policy is for validating the request before processing.
 * <p>
 *
 * The output policy is for building the result page.
 * <p>
 *
 * Each profile can have multiple policy set. Each set is composed of zero or more default policies and zero or more
 * constraint policies.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface IProfile {

    /**
     * Initializes this profile.
     *
     * @param owner profile subsystem
     * @param config configuration store for this profile
     * @exception EBaseException failed to initialize
     */
    public void init(IProfileSubsystem owner, IConfigStore config)
            throws EBaseException;

    /**
     * Retrieves the request queue that is associated with
     * this profile. The request queue is for creating
     * new requests.
     *
     * @return request queue
     */
    public IRequestQueue getRequestQueue();

    /**
     * Sets id of this profile.
     *
     * @param id profile identifier
     */
    public void setId(String id);

    /**
     * Returns the identifier of this profile.
     *
     * @return profile id
     */
    public String getId();

    /**
     * Retrieves a localized string that represents
     * requestor's distinguished name. This string
     * displayed in the request listing user interface.
     *
     * @param request request
     * @return distringuished name of the request owner
     */
    public String getRequestorDN(IRequest request);

    /**
     * Retrieves the configuration store of this profile.
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore();

    /**
     * Retrieves the instance id of the authenticator for this profile.
     *
     * @return authenticator instance id
     */
    public String getAuthenticatorId();

    public String getAuthzAcl();

    /**
     * Sets the instance id of the authenticator for this profile.
     *
     * @param id authenticator instance id
     */
    public void setAuthenticatorId(String id);

    public void setAuthzAcl(String id);

    /**
     * Retrieves the associated authenticator instance.
     *
     * @return profile authenticator instance.
     *         if no associated authenticator, null is returned
     * @exception EProfileException failed to retrieve
     */
    public IProfileAuthenticator getAuthenticator()
            throws EProfileException;

    /**
     * Retrieves a list of input policy IDs.
     *
     * @return input policy id list
     */
    public Enumeration<String> getProfileInputIds();

    /**
     * Retrieves input policy by id.
     *
     * @param id input policy id
     * @return input policy instance
     */
    public IProfileInput getProfileInput(String id);

    /**
     * Retrieves a list of output policy IDs.
     *
     * @return output policy id list
     */
    public Enumeration<String> getProfileOutputIds();

    /**
     * Retrieves output policy by id.
     *
     * @param id output policy id
     * @return output policy instance
     */
    public IProfileOutput getProfileOutput(String id);

    /**
     * Checks if this profile is end-user profile or not.
     * End-user profile will be displayed to the end user.
     * Non end-user profile mainly is for registration
     * manager.
     *
     * @return end-user profile or not
     */
    public boolean isVisible();

    /**
     * Sets this profile end-user profile or not.
     *
     * @param v end-user profile or not
     */
    public void setVisible(boolean v);

    /**
     * Retrieves the user id of the person who
     * approves this profile.
     *
     * @return user id of the approver of this profile
     */
    public String getApprovedBy();

    /*
     * Is this a renewal profile
     */
    public String isRenewal();

    /*
     * is output going to be in xml?
     */
    public String isXmlOutput();

    /**
     * Returns the profile name.
     *
     * @param locale end-user locale
     * @param name profile name
     */
    public void setName(Locale locale, String name);

    /**
     * Retrieves the profile name.
     *
     * @param locale end-user locale
     * @return localized profile name
     */
    public String getName(Locale locale);

    /**
     * Returns the profile description.
     *
     * @param locale end-user locale
     * @param desc profile description
     */
    public void setDescription(Locale locale, String desc);

    /**
     * Retrieves the profile description.
     *
     * @param locale end-user locale
     * @return localized profile description
     */
    public String getDescription(Locale locale);

    /**
     * Retrieves profile context. The context stores
     * information about the requestor before the
     * actual request is created.
     *
     * @return profile context.
     */
    public IProfileContext createContext();

    /**
     * Returns the profile policy set identifiers.
     *
     * @return a list of policy set id
     */
    public Enumeration<String> getProfilePolicySetIds();

    /**
     * Creates a profile policy.
     *
     * @param setId id of the policy set that owns this policy
     * @param id policy id
     * @param defaultClassId id of the registered default implementation
     * @param constraintClassId id of the registered constraint implementation
     * @exception EProfileException failed to create policy
     * @return profile policy instance
     */
    public IProfilePolicy createProfilePolicy(String setId, String id,
            String defaultClassId, String constraintClassId)
            throws EProfileException;

    /**
     * Deletes input policy by id.
     *
     * @param inputId id of the input policy
     * @exception EProfileException failed to delete
     */
    public void deleteProfileInput(String inputId) throws EProfileException;

    /**
     * Delete all profile inputs
     * @throws EProfileException
     */
    public void deleteAllProfileInputs() throws EProfileException;

    /**
     * Deletes output policy by id.
     *
     * @param outputId id of the output policy
     * @exception EProfileException failed to delete
     */
    public void deleteProfileOutput(String outputId) throws EProfileException;

    /**
     * Delete all profile inputs
     * @exception EProfileException
     */
    public void deleteAllProfileOutputs() throws EProfileException;

    /**
     * Creates a input policy.
     *
     * @param id input policy id
     * @param inputClassId id of the registered input implementation
     * @param nvp default parameters
     * @return input policy
     * @exception EProfileException failed to create
     */
    public IProfileInput createProfileInput(String id, String inputClassId,
            NameValuePairs nvp)
            throws EProfileException;

    /**
     * Creates a output policy.
     *
     * @param id output policy id
     * @param outputClassId id of the registered output implementation
     * @param nvp default parameters
     * @return output policy
     * @exception EProfileException failed to create
     */
    public IProfileOutput createProfileOutput(String id, String outputClassId,
            NameValuePairs nvp) throws EProfileException;

    /**
     * Deletes a policy.
     *
     * @param setId id of the policy set
     * @param policyId id of policy to delete
     * @exception EProfileException failed to delete
     */
    public void deleteProfilePolicy(String setId, String policyId)
            throws EProfileException;

    /**
     * Delete all profile policies
     * @exception EProfileException
     */
    public void deleteAllProfilePolicies() throws EProfileException;

    /**
     * Retrieves a policy.
     *
     * @param setId set id
     * @param id policy id
     * @return profile policy
     */
    public IProfilePolicy getProfilePolicy(String setId, String id);

    /**
     * Retrieves all the policy id within a set.
     *
     * @param setId set id
     * @return a list of policy id
     */
    public Enumeration<String> getProfilePolicyIds(String setId);

    /**
     * Retrieves a default set id for the given request.
     * It is the profile's responsibility to return
     * an appropriate set id for the request.
     *
     * @param req request
     * @return policy set id
     */
    public String getPolicySetId(IRequest req);

    /**
     * Returns a list of profile policies.
     *
     * @param setId set id
     * @return a list of policies
     */
    public Enumeration<IProfilePolicy> getProfilePolicies(String setId);

    /**
     * Creates one or more requests. Normally, only one request will
     * be created. In case of CRMF request, multiple requests may be
     * created for one submission.
     *
     * @param ctx profile context
     * @param locale user locale
     * @return a list of requests
     * @exception EProfileException failed to create requests
     */
    public IRequest[] createRequests(IProfileContext ctx, Locale locale)
            throws EProfileException;

    /**
     * Populates user-supplied input values into the requests.
     *
     * @param ctx profile context
     * @param request request
     * @exception EProfileException failed to populate
     */
    public void populateInput(IProfileContext ctx, IRequest request)
            throws EProfileException;

    /**
     * Passes the request to the set of default policies that
     * populate the profile information against the profile.
     *
     * @param request request
     * @exception EProfileException failed to populate default values
     */
    public void populate(IRequest request)
            throws EProfileException;

    /**
     * Passes the request to the set of constraint policies
     * that validate the request against the profile.
     *
     * @param request request
     * @exception ERejectException validation violation
     */
    public void validate(IRequest request)
            throws ERejectException;

    /**
     * Process a request after validation.
     *
     * @param request request to be processed
     * @exception EProfileException failed to process
     */
    public void execute(IRequest request)
            throws EProfileException;

    /**
     * Handles end-user request submission.
     *
     * @param token authentication token
     * @param request request to be processed
     * @exception EDeferException defer request
     * @exception EProfileException failed to submit
     */
    public void submit(IAuthToken token, IRequest request)
            throws EDeferException, EProfileException;

    public void setRenewal(boolean renewal);

    public void setXMLOutput(boolean xmlOutput);
}
