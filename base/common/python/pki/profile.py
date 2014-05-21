#!/usr/bin/python
"""
Created on May 13,, 2014

@author: akoneru
"""

import types

import pki
import pki.client as client
import pki.account as account


class ProfileDataInfo(object):
    """Stores information about a profile"""
    def __init__(self):
        self.profile_id = None
        self.profile_name = None
        self.profile_description = None
        self.profile_url = None

    @classmethod
    def from_json(cls, attr_list):
        profile_data_info = cls()
        profile_data_info.profile_id = attr_list['profileId']
        profile_data_info.profile_name = attr_list['profileName']
        profile_data_info.profile_description = attr_list['profileDescription']
        profile_data_info.profile_url = attr_list['profileURL']

        return profile_data_info


class ProfileDataInfoCollection(object):
    """
    Represents a collection of ProfileDataInfo objects.
    Also encapsulates the links for the list of the objects stored.
    """

    def __init__(self):
        self.profile_data_list = []
        self.links = []

    @classmethod
    def from_json(cls, json_value):
        ret = cls()
        profile_data_infos = json_value['entries']
        if not isinstance(profile_data_infos, types.ListType):
            ret.profile_data_list.append(ProfileDataInfo.from_json(profile_data_infos))
        else:
            for profile_info in profile_data_infos:
                ret.profile_data_list.append(ProfileDataInfo.from_json(profile_info))

        links = json_value['Link']
        if not isinstance(links, types.ListType):
            ret.links.append(pki.Link.from_json(links))
        else:
            for link in links:
                ret.links.append(pki.Link.from_json(link))

        return ret


class Descriptor(object):
    """
    This class represents the description of a ProfileAttribute.
    It stores information such as the syntax, constraint and default value of a profile attribute.
    """

    def __init__(self, syntax=None, constraint=None, description=None, default_value=None):
        self.syntax = syntax
        self.constraint = constraint
        self.description = description
        self.default_value = default_value

    @property
    def syntax(self):
        return getattr(self, 'Syntax', None)

    @syntax.setter
    def syntax(self, value):
        setattr(self, 'Syntax', value)

    @property
    def constraint(self):
        return getattr(self, 'Constraint', None)

    @constraint.setter
    def constraint(self, value):
        setattr(self, 'Constraint', value)

    @property
    def description(self):
        return getattr(self, 'Description', None)

    @description.setter
    def description(self, value):
        setattr(self, 'Description', value)

    @property
    def default_value(self):
        return getattr(self, 'DefaultValue', None)

    @default_value.setter
    def default_value(self, value):
        setattr(self, 'DefaultValue', value)

    @classmethod
    def from_json(cls, attr_list):
        descriptor = cls()
        for attr in attr_list:
            setattr(descriptor, attr, attr_list[attr])

        return descriptor


class ProfileAttribute(object):
    """
    Represents a profile attribute of a ProfileInput.
    """
    def __init__(self, name=None, value=None, descriptor=None):
        self.name = name
        self.value = value
        self.descriptor = descriptor

    @property
    def descriptor(self):
        return getattr(self, 'Descriptor')

    @descriptor.setter
    def descriptor(self, value):
        setattr(self, 'Descriptor', value)

    @property
    def value(self):
        return getattr(self, 'Value')

    @value.setter
    def value(self, value):
        setattr(self, 'Value', value)

    @classmethod
    def from_json(cls, attr_list):
        attribute = cls()
        attribute.name = attr_list['name']
        if 'Value' in attr_list:
            attribute.value = attr_list['Value']
        if 'Descriptor' in attr_list:
            attribute.descriptor = Descriptor.from_json(attr_list['Descriptor'])

        return attribute


class ProfileInput(object):
    """
    This class encapsulates all the attributes of a profile to generate a
    specific property of a certificate.
    Ex. Subject name, Requestor Information etc.
    """

    def __init__(self, profile_input_id=None, class_id=None, name=None, text=None, attributes=None,
                 config_attributes=None):

        self.profile_input_id = profile_input_id
        self.class_id = class_id
        self.name = name
        self.text = text
        if attributes is None:
            self.attributes = []
        if config_attributes is None:
            self.config_attributes = []

    @property
    def profile_input_id(self):
        return getattr(self, 'id')

    @profile_input_id.setter
    def profile_input_id(self, value):
        setattr(self, 'id', value)

    @property
    def class_id(self):
        return getattr(self, 'ClassID', None)

    @class_id.setter
    def class_id(self, value):
        setattr(self, 'ClassID', value)

    @property
    def name(self):
        return getattr(self, 'Name', None)

    @name.setter
    def name(self, value):
        setattr(self, 'Name', value)

    @property
    def text(self):
        return getattr(self, 'Text', None)

    @text.setter
    def text(self, value):
        setattr(self, 'Text', value)

    @property
    def attributes(self):
        return getattr(self, 'Attribute')

    @attributes.setter
    def attributes(self, value):
        setattr(self, 'Attribute', value)

    @property
    def config_attributes(self):
        return getattr(self, 'ConfigAttribute')

    @config_attributes.setter
    def config_attributes(self, value):
        setattr(self, 'ConfigAttribute', value)

    def add_attribute(self, profile_attribute):
        self.attributes.append(profile_attribute)

    def remove_attribute(self, profile_attribute_name):
        for attr in self.attributes:
            if attr.name == profile_attribute_name:
                self.attributes.remove(attr)
                break

    def get_attribute(self, profile_attribute_name):
        for attr in self.attributes:
            if attr.name == profile_attribute_name:
                return attr

        return None

    def add_config_attribute(self, profile_attribute):
        self.attributes.append(profile_attribute)

    def remove_config_attribute(self, config_attribute_name):
        for attr in self.config_attributes:
            if attr.name == config_attribute_name:
                self.attributes.remove(attr)
                break

    def get_config_attribute(self, config_attribute_name):
        for attr in self.attributes:
            if attr.name == config_attribute_name:
                return attr

        return None

    @classmethod
    def from_json(cls, json_value):
        profile_input = cls()
        profile_input.profile_input_id = json_value['id']
        profile_input.class_id = json_value['ClassID']
        profile_input.name = json_value['Name']
        if 'Text' in json_value:
            profile_input.text = json_value['Text']

        attributes = json_value['Attribute']
        if not isinstance(attributes, types.ListType):
            profile_input.attributes.append(ProfileAttribute.from_json(attributes))
        else:
            for profile_info in attributes:
                profile_input.attributes.append(ProfileAttribute.from_json(profile_info))

        config_attributes = json_value['ConfigAttribute']
        if not isinstance(config_attributes, types.ListType):
            profile_input.config_attributes.append(ProfileAttribute.from_json(config_attributes))
        else:
            for config_attribute in config_attributes:
                profile_input.config_attributes.append(ProfileAttribute.from_json(config_attribute))

        return profile_input


class ProfileOutput(object):
    """
    This class defines the output of a certificate enrollment request
    using a profile.
    """

    def __init__(self, profile_output_id=None, name=None, text=None, class_id=None, attributes=None):
        self.profile_output_id = profile_output_id
        self.name = name
        self.text = text
        self.class_id = class_id
        if attributes is None:
            self.attributes = []

    @property
    def profile_output_id(self):
        return getattr(self, 'id')

    @profile_output_id.setter
    def profile_output_id(self, value):
        setattr(self, 'id', value)

    @property
    def class_id(self):
        return getattr(self, 'classId', None)

    @class_id.setter
    def class_id(self, value):
        setattr(self, 'classId', value)

    def add_attribute(self, profile_attribute):
        self.attributes.append(profile_attribute)

    def remove_attribute(self, profile_attribute_name):
        for attr in self.attributes:
            if attr.name == profile_attribute_name:
                self.attributes.remove(attr)
                break

    def get_attribute(self, profile_attribute_name):
        for attr in self.attributes:
            if attr.name == profile_attribute_name:
                return attr

        return None

    @classmethod
    def from_json(cls, json_value):
        profile_output = cls()
        profile_output.profile_output_id = json_value['id']
        profile_output.name = json_value['name']
        if 'text' in json_value:
            profile_output.text = json_value['text']
        profile_output.class_id = json_value['classId']
        attributes = json_value['attributes']
        if not isinstance(attributes, types.ListType):
            profile_output.attributes.append(ProfileAttribute.from_json(attributes))
        else:
            for profile_info in attributes:
                profile_output.attributes.append(ProfileAttribute.from_json(profile_info))
        return profile_output


class ProfileParameter(object):

    def __init__(self, name=None, value=None):
        self.name = name
        self.value = value

    @classmethod
    def from_json(cls, attr_list):
        param = cls()
        for attr in attr_list:
            setattr(param, attr, attr_list[attr])
        return param


class PolicyDefault(object):
    """
    An object of this class contains information of the default usage of a specific ProfileInput.
    """

    def __init__(self, name=None, class_id=None, description=None, policy_attributes=None, policy_params=None):
        self.name = name
        self.class_id = class_id
        self.description = description
        if policy_attributes is None:
            self.policy_attributes = []
        else:
            self.policy_attributes = policy_attributes
        if policy_params is None:
            self.policy_params = []
        else:
            self.policy_params = policy_params

    @property
    def name(self):
        return getattr(self, 'id')

    @name.setter
    def name(self, value):
        setattr(self, 'id', value)

    @property
    def class_id(self):
        return getattr(self, 'classId')

    @class_id.setter
    def class_id(self, value):
        setattr(self, 'classId', value)

    @property
    def policy_attributes(self):
        return getattr(self, 'policyAttribute')

    @policy_attributes.setter
    def policy_attributes(self, value):
        setattr(self, 'policyAttribute', value)

    @property
    def policy_params(self):
        return getattr(self, 'params')

    @policy_params.setter
    def policy_params(self, value):
        setattr(self, 'params', value)

    @classmethod
    def from_json(cls, json_value):
        policy_def = cls()
        if 'id' in json_value:
            policy_def.name = json_value['id']
        if 'classId' in json_value:
            policy_def.class_id = json_value['classId']
        if 'description' in json_value:
            policy_def.description = json_value['description']
        if 'policyAttribute' in json_value:
            attributes = json_value['policyAttribute']
            if not isinstance(attributes, types.ListType):
                policy_def.policy_attributes.append(ProfileAttribute.from_json(attributes))
            else:
                for attr in attributes:
                    policy_def.policy_attributes.append(ProfileAttribute.from_json(attr))

        if 'params' in json_value:
            params = json_value['params']
            if not isinstance(params, types.ListType):
                policy_def.policy_params.append(ProfileParameter.from_json(params))
            else:
                for param in params:
                    policy_def.policy_params.append(ProfileParameter.from_json(param))

        return policy_def


class PolicyConstraintValue(object):

    def __init__(self, name=None, value=None, descriptor=None):
        self.name = name
        self.value = value
        self.descriptor = descriptor

    @property
    def name(self):
        return getattr(self, 'id')

    @name.setter
    def name(self, value):
        setattr(self, 'id', value)

    @classmethod
    def from_json(cls, json_value):
        ret = cls()

        ret.name = json_value['id']
        ret.value = json_value['value']
        if 'descriptor' in json_value:
            ret.descriptor = Descriptor.from_json(json_value['descriptor'])

        return ret


class PolicyConstraint(object):
    """
    An object of this class contains the policy constraints applied to a ProfileInput
    used by a certificate enrollment request.
    """

    def __init__(self, name=None, description=None, class_id=None, policy_constraint_values=None):
        self.name = name
        self.description = description
        self.class_id = class_id
        if policy_constraint_values is None:
            self.policy_constraint_values = []
        else:
            self.policy_constraint_values = policy_constraint_values

    @property
    def name(self):
        return getattr(self, 'id')

    @name.setter
    def name(self, value):
        setattr(self, 'id', value)

    @property
    def class_id(self):
        return getattr(self, 'classId')

    @class_id.setter
    def class_id(self, value):
        setattr(self, 'classId', value)

    @property
    def policy_constraint_values(self):
        return getattr(self, 'constraint')

    @policy_constraint_values.setter
    def policy_constraint_values(self, value):
        setattr(self, 'constraint', value)

    @classmethod
    def from_json(cls, json_value):
        policy_constraint = cls()
        if 'id' in json_value:
            policy_constraint.name = json_value['id']
        if 'description' in json_value:
            policy_constraint.description = json_value['description']
        if 'classId' in json_value:
            policy_constraint.class_id = json_value['classId']
        if 'constraint' in json_value:
            constraints = json_value['constraint']
            if not isinstance(constraints, types.ListType):
                policy_constraint.policy_constraint_values.append(PolicyConstraintValue.from_json(constraints))
            else:
                for constraint in constraints:
                    policy_constraint.policy_constraint_values.append(PolicyConstraintValue.from_json(constraint))

        return policy_constraint


class ProfilePolicy(object):
    """
    This class represents the policy a profile adheres to.
    An object of this class stores the default values for profile and the constraints present on the
    values of the attributes of the profile submitted for an enrollment request.
    """

    def __init__(self, policy_id=None, policy_default=None, policy_constraint=None):
        self.policy_id = policy_id
        self.policy_default = policy_default
        self.policy_constraint = policy_constraint

    @property
    def policy_id(self):
        return getattr(self, 'id')

    @policy_id.setter
    def policy_id(self, value):
        setattr(self, 'id', value)

    @property
    def policy_default(self):
        return getattr(self, 'def')

    @policy_default.setter
    def policy_default(self, value):
        setattr(self, 'def', value)

    @property
    def policy_constraint(self):
        return getattr(self, 'constraint')

    @policy_constraint.setter
    def policy_constraint(self, value):
        setattr(self, 'constraint', value)

    @classmethod
    def from_json(cls, json_value):
        return cls(json_value['id'], PolicyDefault.from_json(json_value['def']),
                   PolicyConstraint.from_json(json_value['constraint']))


class ProfilePolicySet(object):
    """
    Stores a list of ProfilePolicy objects.
    """
    def __init__(self):
        self.policies = []

    @classmethod
    def from_json(cls, attr_list):
        policy_set = cls()

        policies = attr_list['policies']
        if not isinstance(policies, types.ListType):
            policy_set.policies.append(ProfilePolicy.from_json(policies))
        else:
            for policy in policies:
                policy_set.policies.append(ProfilePolicy.from_json(policy))

        return policy_set


class PolicySet(object):
    """
    An object of this class contains a name value pair of the
    policy name and the ProfilePolicy object.
    """
    def __init__(self, name=None, policy_list=None):
        self.name = name
        if policy_list is None:
            self.policy_list = []
        else:
            self.policy_list = policy_list

    @property
    def name(self):
        return getattr(self, 'id')

    @name.setter
    def name(self, value):
        setattr(self, 'id', value)

    @property
    def policy_list(self):
        return getattr(self, 'value')

    @policy_list.setter
    def policy_list(self, value):
        setattr(self, 'value', value)

    @classmethod
    def from_json(cls, json_value):
        policy_set = cls()

        policy_set.name = json_value['id']
        policies = json_value['value']
        if not isinstance(policies, types.ListType):
            policy_set.policy_list.append(ProfilePolicy.from_json(policies))
        else:
            for policy in policies:
                policy_set.policy_list.append(ProfilePolicy.from_json(policy))


class PolicySetList(object):
    """
    An object of this class stores a list of ProfileSet objects.
    """

    def __init__(self, policy_sets=None):
        if policy_sets is None:
            self.policy_sets = []
        else:
            self.policy_sets = policy_sets

    @property
    def policy_sets(self):
        return getattr(self, 'PolicySet')

    @policy_sets.setter
    def policy_sets(self, value):
        setattr(self, 'PolicySet', value)

    @classmethod
    def from_json(cls, json_value):
        policy_set_list = cls()
        policy_sets = json_value['PolicySet']
        if not isinstance(policy_sets, types.ListType):
            policy_set_list.policy_sets.append(PolicySet.from_json(policy_sets))
        else:
            for policy_set in policy_sets:
                policy_set_list.policy_sets.append(PolicySet.from_json(policy_set))


class ProfileData(object):
    """
    This class represents an enrollment profile.
    """

    def __init__(self, profile_id=None, class_id=None, name=None, description=None, enabled=None, visible=None,
                 enabled_by=None, authenticator_id=None, authorization_acl=None, renewal=None, xml_output=None,
                 inputs=None, outputs=None, policy_sets=None, link=None):

        self.profile_id = profile_id
        self.name = name
        self.class_id = class_id
        self.description = description
        self.enabled = enabled
        self.visible = visible
        self.enabled_by = enabled_by
        self.authenticator_id = authenticator_id
        self.authorization_acl = authorization_acl
        self.renewal = renewal
        self.xml_output = xml_output
        if inputs is None:
            self.inputs = []
        else:
            self.inputs = inputs
        if outputs is None:
            self.outputs = []
        else:
            self.outputs = outputs
        if policy_sets is None:
            self.policy_sets = []
        else:
            self.policy_sets = policy_sets
        self.link = link

    @property
    def profile_id(self):
        return getattr(self, 'id')

    @profile_id.setter
    def profile_id(self, value):
        setattr(self, 'id', value)

    @property
    def class_id(self):
        return getattr(self, 'classId')

    @class_id.setter
    def class_id(self, value):
        setattr(self, 'classId', value)

    @property
    def enabled_by(self):
        return getattr(self, 'enabledBy')

    @enabled_by.setter
    def enabled_by(self, value):
        setattr(self, 'enabledBy', value)

    @property
    def authenticator_id(self):
        return getattr(self, 'authenticatorId')

    @authenticator_id.setter
    def authenticator_id(self, value):
        setattr(self, 'authenticatorId', value)

    @property
    def authorization_acl(self):
        return getattr(self, 'authzAcl')

    @authorization_acl.setter
    def authorization_acl(self, value):
        setattr(self, 'authzAcl', value)

    @property
    def xml_output(self):
        return getattr(self, 'xmlOutput')

    @xml_output.setter
    def xml_output(self, value):
        setattr(self, 'xmlOutput', value)

    @property
    def inputs(self):
        return getattr(self, 'Input')

    @inputs.setter
    def inputs(self, value):
        setattr(self, 'Input', value)

    @property
    def outputs(self):
        return getattr(self, 'Output')

    @outputs.setter
    def outputs(self, value):
        setattr(self, 'Output', value)

    @property
    def policy_sets(self):
        return getattr(self, 'PolicySets')

    @policy_sets.setter
    def policy_sets(self, value):
        setattr(self, 'PolicySets', value)

    @classmethod
    def from_json(cls, json_value):
        profile_data = cls()
        profile_data.profile_id = json_value['id']
        profile_data.class_id = json_value['classId']
        profile_data.name = json_value['name']
        profile_data.description = json_value['description']
        profile_data.enabled = json_value['enabled']
        profile_data.visible = json_value['visible']
        if 'enabledBy' in json_value:
            profile_data.enabled_by = json_value['enabledBy']
        if 'authenticatorId' in json_value:
            profile_data.authenticator_id = json_value['authenticatorId']
        profile_data.authorization_acl = json_value['authzAcl']
        profile_data.renewal = json_value['renewal']
        profile_data.xml_output = json_value['xmlOutput']

        profile_inputs = json_value['Input']
        if not isinstance(profile_inputs, types.ListType):
            profile_data.inputs.append(ProfileInput.from_json(profile_inputs))
        else:
            for profile_input in profile_inputs:
                profile_data.policy_sets.append(ProfileInput.from_json(profile_input))

        profile_outputs = json_value['Output']
        if not isinstance(profile_outputs, types.ListType):
            profile_data.outputs.append(ProfileOutput.from_json(profile_outputs))
        else:
            for profile_output in profile_outputs:
                profile_data.policy_sets.append(ProfileOutput.from_json(profile_output))

        policy_sets = json_value['PolicySets']
        if not isinstance(policy_sets, types.ListType):
            profile_data.policy_sets.append(PolicySetList.from_json(policy_sets))
        else:
            for policy_set in policy_sets:
                profile_data.policy_sets.append(PolicySetList.from_json(policy_set))

        profile_data.link = pki.Link.from_json(json_value['link'])

        return profile_data


class ProfileClient(object):
    """
    This class consists of methods for accessing the ProfileResource.
    """
    def __init__(self, connection):
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.profiles_url = '/rest/profiles'
        self.account_client = account.AccountClient(connection)

    def _get(self, url, query_params=None, payload=None):
        self.account_client.login()
        r = self.connection.get(url, self.headers, query_params, payload)
        self.account_client.logout()
        return r

    def _post(self, url, payload=None, query_params=None):
        self.account_client.login()
        r = self.connection.post(url, payload, self.headers, query_params)
        self.account_client.logout()
        return r

    @pki.handle_exceptions()
    def list_profiles(self, start=None, size=None):
        """
        Fetches the list of profiles.
        The start and size arguments provide pagination support.
        Returns a ProfileDataInfoCollection object.
        """
        query_params = {
            'start': start,
            'size': size
        }
        r = self._get(self.profiles_url, query_params)
        return ProfileDataInfoCollection.from_json(r.json())

    @pki.handle_exceptions()
    def get_profile(self, profile_id):
        """
        Fetches information for the profile for the given profile id.
        Returns a ProfileData object.
        """
        if profile_id is None:
            raise ValueError("Profile ID must be specified.")
        url = self.profiles_url + '/' + str(profile_id)
        r = self._get(url)
        return ProfileData.from_json(r.json())

    def _modify_profile_state(self, profile_id, action):
        """
        Internal method used to modify the profile state.
        """
        if profile_id is None:
            raise ValueError("Profile ID must be specified.")
        if action is None:
            raise ValueError("A valid action(enable/disable) must be specified.")

        url = self.profiles_url + '/' + str(profile_id)
        params = {'action': action}
        self._post(url, query_params=params)

    @pki.handle_exceptions()
    def enable_profile(self, profile_id):
        """
        Enables a profile.
        """
        return self._modify_profile_state(profile_id, 'enable')

    @pki.handle_exceptions()
    def disable_profile(self, profile_id):
        """
        Disables a profile.
        """
        return self._modify_profile_state(profile_id, 'disable')


def main():
    # Initialize a PKIConnection object for the CA
    connection = client.PKIConnection('https', 'localhost', '8443', 'ca')

    # The pem file used for authentication. Created from a p12 file using the command -
    # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
    connection.set_authentication_cert("/tmp/auth.pem")

    #Initialize the ProfileClient class
    profile_client = ProfileClient(connection)

    #Fetching a list of profiles
    profile_data_infos = profile_client.list_profiles()
    print('List of profiles:')
    print('-----------------')
    for profile_data_info in profile_data_infos.profile_data_list:
        print('  Profile ID: ' + profile_data_info.profile_id)
        print('  Profile Name: ' + profile_data_info.profile_name)
        print('  Profile Description: ' + profile_data_info.profile_description)
    print

    # Get a specific profile
    profile_data = profile_client.get_profile('caUserCert')
    print('Profile Data for caUserCert:')
    print('----------------------------')
    print('  Profile ID: ' + profile_data.profile_id)
    print('  Profile Name: ' + profile_data.name)
    print('  Profile Description: ' + profile_data.description)
    print('  Is profile enabled? ' + str(profile_data.enabled))
    print('  Is profile visible? ' + str(profile_data.visible))
    print

    # Disabling a profile
    print('Disabling a profile:')
    print('--------------------')
    profile_client.disable_profile('caUserCert')
    profile = profile_client.get_profile('caUserCert')
    print('  Profile ID: ' + profile.profile_id)
    print('  Is profile enabled? ' + str(profile.enabled))
    print

    # Disabling a profile
    print('Enabling a profile:')
    print('-------------------')
    profile_client.enable_profile('caUserCert')
    profile = profile_client.get_profile('caUserCert')
    print('  Profile ID: ' + profile_data.profile_id)
    print('  Is profile enabled? ' + str(profile.enabled))
    print


if __name__ == "__main__":
    main()