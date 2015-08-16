#!/usr/bin/python
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2014 Red Hat, Inc.
# All rights reserved.
#
# @author: Abhishek Koneru <akoneru@redhat.com>

from __future__ import absolute_import
from __future__ import print_function
import json
import os

from six import iteritems

import pki
import pki.client as client
import pki.account as account
import pki.encoder as encoder


class ProfileDataInfo(object):
    """Stores information about a profile"""

    json_attribute_names = {
        'profileId': 'profile_id', 'profileName': 'profile_name',
        'profileDescription': 'profile_description', 'profileURL': 'profile_url'
    }

    def __init__(self):
        self.profile_id = None
        self.profile_name = None
        self.profile_description = None
        self.profile_url = None

    def __repr__(self):
        attributes = {
            "ProfileDataInfo": {
                'profile_id': self.profile_id,
                'name': self.profile_name,
                'description': self.profile_description,
                'url': self.profile_url
            }
        }
        return str(attributes)

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        profile_data_info = cls()
        for k, v in iteritems(attr_list):
            if k in ProfileDataInfo.json_attribute_names:
                setattr(profile_data_info,
                        ProfileDataInfo.json_attribute_names[k], v)
            else:
                setattr(profile_data_info, k, v)

        return profile_data_info


class ProfileDataInfoCollection(object):
    """
    Represents a collection of ProfileDataInfo objects.
    Also encapsulates the links for the list of the objects stored.
    """

    def __init__(self):
        self.profile_data_list = []
        self.links = []

    def __iter__(self):
        return iter(self.profile_data_list)

    @classmethod
    def from_json(cls, attr_list):
        ret = cls()
        profile_data_infos = attr_list['entries']
        if not isinstance(profile_data_infos, list):
            ret.profile_data_list.append(
                ProfileDataInfo.from_json(profile_data_infos))
        else:
            for profile_info in profile_data_infos:
                ret.profile_data_list.append(
                    ProfileDataInfo.from_json(profile_info))

        links = attr_list['Link']
        if not isinstance(links, list):
            ret.links.append(pki.Link.from_json(links))
        else:
            for link in links:
                ret.links.append(pki.Link.from_json(link))

        return ret


class Descriptor(object):
    """
    This class represents the description of a ProfileAttribute.
    It stores information such as the syntax, constraint and default value of
    a profile attribute.
    """

    json_attribute_names = {
        'Syntax': 'syntax', 'Description': 'description',
        'Constraint': 'constraint', 'DefaultValue': 'default_value'
    }

    def __init__(self, syntax=None, constraint=None, description=None,
                 default_value=None):
        self.syntax = syntax
        self.constraint = constraint
        self.description = description
        self.default_value = default_value

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        descriptor = cls()
        for k, v in iteritems(attr_list):
            if k in Descriptor.json_attribute_names:
                setattr(descriptor,
                        Descriptor.json_attribute_names[k], v)
            else:
                setattr(descriptor, k, v)

        return descriptor


class ProfileAttribute(object):
    """
    Represents a profile attribute of a ProfileInput.
    """
    json_attribute_names = {
        'Value': 'value', 'Descriptor': 'descriptor'
    }

    def __init__(self, name=None, value=None, descriptor=None):
        self.name = name
        self.value = value
        self.descriptor = descriptor

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        attribute = cls()
        attribute.name = attr_list['name']
        if 'Value' in attr_list:
            attribute.value = attr_list['Value']
        if 'Descriptor' in attr_list:
            attribute.descriptor = Descriptor.from_json(
                attr_list['Descriptor'])

        return attribute


class ProfileInput(object):
    """
    This class encapsulates all the attributes of a profile to generate a
    specific property of a certificate.
    Ex. Subject name, Requestor Information etc.
    """

    json_attribute_names = {
        'id': 'profile_input_id', 'ClassID': 'class_id', 'Name': 'name',
        'Text': 'text', 'Attribute': 'attributes',
        'ConfigAttribute': 'config_attributes'
    }

    def __init__(self, profile_input_id=None, class_id=None, name=None,
                 text=None, attributes=None, config_attributes=None):

        self.profile_input_id = profile_input_id
        self.class_id = class_id
        self.name = name
        self.text = text
        if attributes is None:
            self.attributes = []
        else:
            self.attributes = attributes
        if config_attributes is None:
            self.config_attributes = []
        else:
            self.config_attributes = config_attributes

    def add_attribute(self, profile_attribute):
        """
        Add a ProfileAttribute object to the attributes list.
        """
        if not isinstance(profile_attribute, ProfileAttribute):
            raise ValueError("Object passed is not a ProfileAttribute.")
        self.attributes.append(profile_attribute)

    def remove_attribute(self, profile_attribute_name):
        """
        Remove a ProfileAttribute object with the given name from the attributes
        list.
        """
        for attr in self.attributes:
            if attr.name == profile_attribute_name:
                self.attributes.remove(attr)
                break

    def get_attribute(self, profile_attribute_name):
        """
        Returns a ProfileAttribute object for the given name.
        None, if no match.
        """
        for attr in self.attributes:
            if attr.name == profile_attribute_name:
                return attr

        return None

    def add_config_attribute(self, profile_attribute):
        """
        Add a ProfileAttribute object to the config_attributes list.
        """
        if not isinstance(profile_attribute, ProfileAttribute):
            raise ValueError("Object passed is not a ProfileAttribute.")
        self.config_attributes.append(profile_attribute)

    def remove_config_attribute(self, config_attribute_name):
        """
        Remove a ProfileAttribute object with the given name from the
        config_attributes list.
        """
        for attr in self.config_attributes:
            if attr.name == config_attribute_name:
                self.config_attributes.remove(attr)
                break

    def get_config_attribute(self, config_attribute_name):
        """
        Returns a ProfileAttribute object with the given name.
        None, if there is no match in the config_attributes list.
        """
        for attr in self.config_attributes:
            if attr.name == config_attribute_name:
                return attr

        return None

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None
        profile_input = cls()

        for k, v in iteritems(attr_list):
            if k not in ['Attribute', 'ConfigAttribute']:
                if k in ProfileInput.json_attribute_names:
                    setattr(profile_input,
                            ProfileInput.json_attribute_names[k], v)
                else:
                    setattr(profile_input, k, v)

        attributes = attr_list['Attribute']
        if not isinstance(attributes, list):
            profile_input.attributes.append(
                ProfileAttribute.from_json(attributes))
        else:
            for profile_info in attributes:
                profile_input.attributes.append(
                    ProfileAttribute.from_json(profile_info))

        config_attributes = attr_list['ConfigAttribute']
        if not isinstance(config_attributes, list):
            profile_input.config_attributes.append(
                ProfileAttribute.from_json(config_attributes))
        else:
            for config_attribute in config_attributes:
                profile_input.config_attributes.append(
                    ProfileAttribute.from_json(config_attribute))

        return profile_input


class ProfileOutput(object):
    """
    This class defines the output of a certificate enrollment request
    using a profile.
    """

    json_attribute_names = {
        'id': 'profile_output_id', 'classId': 'class_id'
    }

    def __init__(self, profile_output_id=None, name=None, text=None,
                 class_id=None, attributes=None):
        self.profile_output_id = profile_output_id
        self.name = name
        self.text = text
        self.class_id = class_id
        if attributes is None:
            self.attributes = []
        else:
            self.attributes = attributes

    def add_attribute(self, profile_attribute):
        """
        Add a ProfileAttribute object to the attributes list.
        """
        if not isinstance(profile_attribute, ProfileAttribute):
            raise ValueError("Object passed is not a ProfileAttribute.")
        self.attributes.append(profile_attribute)

    def remove_attribute(self, profile_attribute_name):
        """
        Remove a ProfileAttribute object with the given name from the attributes
        list.
        """
        for attr in self.attributes:
            if attr.name == profile_attribute_name:
                self.attributes.remove(attr)
                break

    def get_attribute(self, profile_attribute_name):
        """
        Returns a ProfileAttribute object for the given name.
        None, if no match.
        """
        for attr in self.attributes:
            if attr.name == profile_attribute_name:
                return attr

        return None

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        profile_output = cls()
        for k, v in iteritems(attr_list):
            if k not in ['attributes']:
                if k in ProfileOutput.json_attribute_names:
                    setattr(profile_output,
                            ProfileOutput.json_attribute_names[k], v)
                else:
                    setattr(profile_output, k, v)

        attributes = attr_list['attributes']
        if not isinstance(attributes, list):
            profile_output.attributes.append(
                ProfileAttribute.from_json(attributes))
        else:
            for profile_info in attributes:
                profile_output.attributes.append(
                    ProfileAttribute.from_json(profile_info))
        return profile_output


class ProfileParameter(object):
    def __init__(self, name=None, value=None):
        self.name = name
        self.value = value

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        param = cls()
        for attr in attr_list:
            setattr(param, attr, attr_list[attr])
        return param


class PolicyDefault(object):
    """
    An object of this class contains information of the default usage of a
    specific ProfileInput.
    """

    json_attribute_names = {
        'id': 'name', 'classId': 'class_id',
        'policyAttribute': 'policy_attributes', 'params': 'policy_params'
    }

    def __init__(self, name=None, class_id=None, description=None,
                 policy_attributes=None, policy_params=None):
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

    def add_attribute(self, policy_attribute):
        """
        Add a policy attribute to the attribute list.
        @param policy_attribute - A ProfileAttribute object
        """
        if not isinstance(policy_attribute, ProfileAttribute):
            raise ValueError("Object passed is not a ProfileAttribute.")
        self.policy_attributes.append(policy_attribute)

    def remove_attribute(self, policy_attribute_name):
        """
        Remove a policy attribute with the given name from the attributes list.
        """
        for attr in self.policy_attributes:
            if attr.name == policy_attribute_name:
                self.policy_attributes.remove(attr)
                break

    def get_attribute(self, policy_attribute_name):
        """
        Fetch the policy attribute with the given name from the attributes list.
        """
        for attr in self.policy_attributes:
            if attr.name == policy_attribute_name:
                return attr

        return None

    def add_parameter(self, policy_parameter):
        """
        Add a profile parameter to the parameters list.
        @param policy_parameter - A ProfileParameter object.
        """
        if not isinstance(policy_parameter, ProfileParameter):
            raise ValueError("Object passed is not a ProfileParameter.")
        self.policy_params.append(policy_parameter)

    def remove_parameter(self, profile_parameter_name):
        """
        Remove a profile parameter with the given name from the parameters list.
        """
        for param in self.policy_params:
            if param.name == profile_parameter_name:
                self.policy_params.remove(param)
                break

    def get_parameter(self, profile_parameter_name):
        """
        Fetch a profile parameter with the given name from the parameters list.
        """
        for param in self.policy_params:
            if param.name == profile_parameter_name:
                return param

        return None

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        policy_def = cls()
        for k, v in iteritems(attr_list):
            if k not in ['policyAttribute', 'params']:
                if k in PolicyDefault.json_attribute_names:
                    setattr(policy_def,
                            PolicyDefault.json_attribute_names[k], v)
                else:
                    setattr(policy_def, k, v)

        if 'policyAttribute' in attr_list:
            attributes = attr_list['policyAttribute']
            if not isinstance(attributes, list):
                policy_def.policy_attributes.append(
                    ProfileAttribute.from_json(attributes))
            else:
                for attr in attributes:
                    policy_def.policy_attributes.append(
                        ProfileAttribute.from_json(attr))

        if 'params' in attr_list:
            params = attr_list['params']
            if not isinstance(params, list):
                policy_def.policy_params.append(
                    ProfileParameter.from_json(params))
            else:
                for param in params:
                    policy_def.policy_params.append(
                        ProfileParameter.from_json(param))

        return policy_def


class PolicyConstraintValue(object):
    """
    Represents a PolicyConstraintValue
    """

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
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        ret = cls()
        ret.name = attr_list['id']
        ret.value = attr_list['value']
        if 'descriptor' in attr_list:
            ret.descriptor = Descriptor.from_json(attr_list['descriptor'])

        return ret


class PolicyConstraint(object):
    """
    An object of this class contains the policy constraints applied to a
    ProfileInput used by a certificate enrollment request.
    """

    json_attribute_names = {
        'id': 'name', 'classId': 'class_id',
        'constraint': 'policy_constraint_values'
    }

    def __init__(self, name=None, description=None, class_id=None,
                 policy_constraint_values=None):
        self.name = name
        self.description = description
        self.class_id = class_id
        if policy_constraint_values is None:
            self.policy_constraint_values = []
        else:
            self.policy_constraint_values = policy_constraint_values

    def add_constraint_value(self, policy_constraint_value):
        """
        Add a PolicyConstraintValue to the policy_constraint_values list.
        """
        if not isinstance(policy_constraint_value, PolicyConstraintValue):
            raise ValueError("Object passed not of type PolicyConstraintValue")
        self.policy_constraint_values.append(policy_constraint_value)

    def remove_constraint_value(self, policy_constraint_value_name):
        """
        Removes a PolicyConstraintValue with the given name form the
        policy_constraint_values list.
        """
        for attr in self.policy_constraint_values:
            if attr.name == policy_constraint_value_name:
                self.policy_constraint_values.remove(attr)
                break

    def get_constraint_value(self, policy_constraint_value_name):
        """
        Returns a PolicyConstraintValue object with the given name.
        None, if there is no match.
        """
        for constraint in self.policy_constraint_values:
            if constraint.name == policy_constraint_value_name:
                return constraint

        return None

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        policy_constraint = cls()
        for k, v in iteritems(attr_list):
            if k not in ['constraint']:
                if k in PolicyConstraint.json_attribute_names:
                    setattr(policy_constraint,
                            PolicyConstraint.json_attribute_names[k], v)
                else:
                    setattr(policy_constraint, k, v)

        if 'constraint' in attr_list:
            constraints = attr_list['constraint']
            if not isinstance(constraints, list):
                policy_constraint.add_constraint_value(
                    PolicyConstraintValue.from_json(constraints))
            else:
                for constraint in constraints:
                    policy_constraint.add_constraint_value(
                        PolicyConstraintValue.from_json(constraint))

        return policy_constraint


class ProfilePolicy(object):
    """
    This class represents the policy a profile adheres to.
    An object of this class stores the default values for profile and the
    constraints present on the values of the attributes of the profile submitted
    for an enrollment request.
    """

    json_attribute_names = {
        'id': 'policy_id', 'def': 'policy_default',
        'constraint': 'policy_constraint'
    }

    def __init__(self, policy_id=None, policy_default=None,
                 policy_constraint=None):
        self.policy_id = policy_id
        self.policy_default = policy_default
        self.policy_constraint = policy_constraint

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None
        policy = cls()

        policy.policy_id = attr_list['id']
        if 'def' in attr_list:
            policy.policy_default = PolicyDefault.from_json(attr_list['def'])
        if 'constraint' in attr_list:
            policy.policy_constraint = \
                PolicyConstraint.from_json(attr_list['constraint'])

        return policy


class ProfilePolicySet(object):
    """
    Stores a list of ProfilePolicy objects.
    """

    def __init__(self):
        self.policies = []

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        policy_set = cls()

        policies = attr_list['policies']
        if not isinstance(policies, list):
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

    json_attribute_names = {
        'id': 'name', 'value': 'policy_list'
    }

    def __init__(self, name=None, policy_list=None):
        self.name = name
        if policy_list is None:
            self.policy_list = []
        else:
            self.policy_list = policy_list

    def add_policy(self, profile_policy):
        """
        Add a ProfilePolicy object to the policy_list
        """
        if not isinstance(profile_policy, ProfilePolicy):
            raise ValueError("Object passed is not a ProfilePolicy.")
        self.policy_list.append(profile_policy)

    def remove_policy(self, policy_id):
        """
        Removes a ProfilePolicy with the given ID from the PolicySet.
        """
        for policy in self.policy_list:
            if policy.policy_id == policy_id:
                self.policy_list.remove(policy)
                break

    def get_policy(self, policy_id):
        """
        Returns a ProfilePolicy object with the given profile id.
        """
        for policy in self.policy_list:
            if policy.policy_id == policy_id:
                return policy
        return None

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        policy_set = cls()

        policy_set.name = attr_list['id']
        policies = attr_list['value']
        if not isinstance(policies, list):
            policy_set.policy_list.append(ProfilePolicy.from_json(policies))
        else:
            for policy in policies:
                policy_set.policy_list.append(ProfilePolicy.from_json(policy))

        return policy_set


class PolicySetList(object):
    """
    An object of this class stores a list of ProfileSet objects.
    """

    def __init__(self, policy_sets=None):
        if policy_sets is None:
            self.policy_sets = []
        else:
            self.policy_sets = policy_sets

    def __iter__(self):
        return iter(self.policy_sets)

    @property
    def policy_sets(self):
        return getattr(self, 'PolicySet')

    @policy_sets.setter
    def policy_sets(self, value):
        setattr(self, 'PolicySet', value)

    def add_policy_set(self, policy_set):
        """
        Add a PolicySet object to the policy_sets list.
        """
        if not isinstance(policy_set, PolicySet):
            raise ValueError("Object passed is not a PolicySet.")
        self.policy_sets.append(policy_set)

    def remove_policy_set(self, policy_set_name):
        """
        Remove a PolicySet object with the given name from the policy_sets list.
        """
        for policy_set in self.policy_sets:
            if policy_set.name == policy_set_name:
                self.policy_sets.remove(policy_set)
                break

    def get_policy_set(self, policy_set_name):
        """
        Fetch the PolicySet object for the given name.
        Returns None, if not found.
        """
        for policy_set in self.policy_sets:
            if policy_set.name == policy_set_name:
                return policy_set
        return None

    @classmethod
    def from_json(cls, attr_list):
        if attr_list is None:
            return None

        policy_set_list = cls()
        policy_sets = attr_list['PolicySet']
        if not isinstance(policy_sets, list):
            policy_set_list.policy_sets.append(
                PolicySet.from_json(policy_sets))
        else:
            for policy_set in policy_sets:
                policy_set_list.policy_sets.append(
                    PolicySet.from_json(policy_set))

        return policy_set_list


class Profile(object):
    """
    This class represents an enrollment profile.
    """

    json_attribute_names = {
        'id': 'profile_id', 'classId': 'class_id', 'enabledBy': 'enabled_by',
        'authenticatorId': 'authenticator_id', 'authzAcl': 'authorization_acl',
        'xmlOutput': 'xml_output', 'Input': 'inputs', 'Output': 'outputs',
        'PolicySets': 'policy_set_list'
    }

    def __init__(self, profile_id=None, class_id=None, name=None,
                 description=None, enabled=None, visible=None, enabled_by=None,
                 authenticator_id=None, authorization_acl=None, renewal=None,
                 xml_output=None, inputs=None, outputs=None,
                 policy_set_list=None, link=None):

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
        if policy_set_list is None:
            self.policy_set_list = PolicySetList()
        else:
            self.policy_set_list = policy_set_list
        self.link = link

    def add_input(self, profile_input):
        """
        Add a ProfileInput object to the inputs list of the Profile.
        """
        if not isinstance(profile_input, ProfileInput):
            raise ValueError("Object passed is not a PolicyInput.")
        if profile_input is None:
            raise ValueError("No ProfileInput object provided.")
        self.inputs.append(profile_input)

    def remove_input(self, profile_input_id):
        """
        Remove a ProfileInput from the inputs list of the Profile.
        """
        for profile_input in self.inputs:
            if profile_input_id == profile_input.profile_input_id:
                self.inputs.remove(profile_input)
                break

    def get_input(self, profile_input_id):
        """
        Fetches a ProfileInput with the given ProfileInput id.
        Returns None, if there is no matching input.
        """
        for profile_input in self.inputs:
            if profile_input_id == profile_input.profile_input_id:
                return profile_input
        return None

    def add_output(self, profile_output):
        """
        Add a ProfileOutput object to the outputs list of the Profile.
        """
        if not isinstance(profile_output, ProfileOutput):
            raise ValueError("Object passed is not a PolicyOutput.")
        if profile_output is None:
            raise ValueError("No ProfileOutput object provided.")
        self.outputs.append(profile_output)

    def remove_output(self, profile_output_id):
        """
        Remove a ProfileOutput from the outputs list of the Profile.
        """
        for profile_output in self.outputs:
            if profile_output_id == profile_output.profile_output_id:
                self.inputs.remove(profile_output)

    def get_output(self, profile_output_id):
        """
        Fetches a ProfileOutput with the given ProfileOutput id.
        Returns None, if there is no matching output.
        """
        for profile_input in self.inputs:
            if profile_output_id == profile_input.profile_input_id:
                return profile_input
        return None

    def add_policy_set(self, policy_set):
        """
        Add a PolicySet object to the policy_sets list of the Profile.
        """
        if policy_set is None:
            raise ValueError("No PolicySet object provided.")
        self.policy_set_list.add_policy_set(policy_set)

    def remove_policy_set(self, policy_set_name):
        """
        Remove a PolicySet from the policy_sets list of the Profile.
        """
        self.policy_set_list.remove_policy_set(policy_set_name)

    def get_policy_set(self, policy_set_name):
        """
        Fetches a ProfileInput with the given ProfileInput id.
        Returns None, if there is no matching input.
        """
        return self.policy_set_list.get_policy_set(policy_set_name)

    @classmethod
    def from_json(cls, attr_list):
        profile_data = cls()
        for k, v in iteritems(attr_list):
            if k not in ['Input', 'Output', 'PolicySets']:
                if k in Profile.json_attribute_names:
                    setattr(profile_data,
                            Profile.json_attribute_names[k], v)
                else:
                    setattr(profile_data, k, v)

        profile_inputs = attr_list['Input']
        if not isinstance(profile_inputs, list):
            profile_data.inputs.append(ProfileInput.from_json(profile_inputs))
        else:
            for profile_input in profile_inputs:
                profile_data.inputs.append(
                    ProfileInput.from_json(profile_input))

        profile_outputs = attr_list['Output']
        if not isinstance(profile_outputs, list):
            profile_data.outputs.append(
                ProfileOutput.from_json(profile_outputs))
        else:
            for profile_output in profile_outputs:
                profile_data.outputs.append(
                    ProfileOutput.from_json(profile_output))

        profile_data.policy_set_list = \
            PolicySetList.from_json(attr_list['PolicySets'])

        profile_data.link = pki.Link.from_json(attr_list['link'])

        return profile_data

    def __repr__(self):
        attributes = {
            "ProfileData": {
                'profile_id': self.profile_id,
                'name': self.name,
                'description': self.description,
                'status': ('enabled' if self.enabled else 'disabled'),
                'visible': self.visible
            }
        }
        return str(attributes)

    @staticmethod
    def get_profile_data_from_file(path_to_file):
        """
        Reads the file for the serialized Profile object.
        Currently supports only data format in json.
        """
        if path_to_file is None:
            raise ValueError("File path must be specified.")
        with open(path_to_file) as input_file:
            data = input_file.read()
            if data is not None:
                return Profile.from_json(json.loads(data))
        return None


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

    def _put(self, url, payload=None):
        self.account_client.login()
        r = self.connection.put(url, payload, self.headers)
        self.account_client.logout()
        return r

    def _delete(self, url):
        self.account_client.login()
        r = self.connection.delete(url, self.headers)
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
        return Profile.from_json(r.json())

    def _modify_profile_state(self, profile_id, action):
        """
        Internal method used to modify the profile state.
        """
        if profile_id is None:
            raise ValueError("Profile ID must be specified.")
        if action is None:
            raise ValueError("A valid action(enable/disable) must be "
                             "specified.")

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

    def _send_profile_create(self, profile_data):

        if profile_data is None:
            raise ValueError("No ProfileData specified")

        profile_object = json.dumps(profile_data, cls=encoder.CustomTypeEncoder,
                                    sort_keys=True)

        r = self._post(self.profiles_url, profile_object)

        return Profile.from_json(r.json())

    def _send_profile_modify(self, profile_data):
        if profile_data is None:
            raise ValueError("No ProfileData specified")
        if profile_data.profile_id is None:
            raise ValueError("Profile Id is not specified.")
        profile_object = json.dumps(profile_data, cls=encoder.CustomTypeEncoder,
                                    sort_keys=True)
        url = self.profiles_url + '/' + str(profile_data.profile_id)
        r = self._put(url, profile_object)

        return Profile.from_json(r.json())

    @pki.handle_exceptions()
    def create_profile(self, profile_data):
        """
        Create a new profile for the given Profile object.
        """
        return self._send_profile_create(profile_data)

    @pki.handle_exceptions()
    def modify_profile(self, profile_data):
        """
        Modify an existing profile with the given Profile object.
        """
        return self._send_profile_modify(profile_data)

    def create_profile_from_file(self, path_to_file):
        """
        Reads the file for the serialized Profile object.
        Performs the profile create operation.
        Currently supports only data format in json.
        """
        profile_data = Profile.get_profile_data_from_file(path_to_file)
        return self._send_profile_create(profile_data)

    def modify_profile_from_file(self, path_to_file):
        """
        Reads the file for the serialized Profile object.
        Performs the profile modify operation.
        Currently supports only data format in json.
        """
        profile_data = Profile.get_profile_data_from_file(path_to_file)
        return self._send_profile_modify(profile_data)

    @pki.handle_exceptions()
    def delete_profile(self, profile_id):
        """
        Delete a profile with the given Profile Id.
        """
        if profile_id is None:
            raise ValueError("Profile Id must be specified.")

        url = self.profiles_url + '/' + str(profile_id)
        r = self._delete(url)
        return r

    encoder.NOTYPES['Profile'] = Profile
    encoder.NOTYPES['ProfileInput'] = ProfileInput
    encoder.NOTYPES['ProfileOutput'] = ProfileOutput
    encoder.NOTYPES['ProfileAttribute'] = ProfileAttribute
    encoder.NOTYPES['Descriptor'] = Descriptor
    encoder.NOTYPES['PolicySetList'] = PolicySetList
    encoder.NOTYPES['PolicySet'] = PolicySet
    encoder.NOTYPES['ProfilePolicy'] = ProfilePolicy
    encoder.NOTYPES['PolicyDefault'] = PolicyDefault
    encoder.NOTYPES['PolicyConstraint'] = PolicyConstraint
    encoder.NOTYPES['ProfileParameter'] = ProfileParameter
    encoder.NOTYPES['PolicyConstraintValue'] = PolicyConstraintValue
    encoder.NOTYPES['Link'] = pki.Link


def main():
    # Initialize a PKIConnection object for the CA
    connection = client.PKIConnection('https', 'localhost', '8443', 'ca')

    # The pem file used for authentication. Created from a p12 file using the
    # command -
    # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
    connection.set_authentication_cert("/tmp/auth.pem")

    # Initialize the ProfileClient class
    profile_client = ProfileClient(connection)

    # Folder to store the files generated during test
    file_path = '/tmp/profile_client_test/'
    if not os.path.exists(file_path):
        os.makedirs(file_path)

    # Fetching a list of profiles
    profile_data_infos = profile_client.list_profiles()
    print('List of profiles:')
    print('-----------------')
    for profile_data_info in profile_data_infos:
        print('  Profile ID: ' + profile_data_info.profile_id)
        print('  Profile Name: ' + profile_data_info.profile_name)
        print('  Profile Description: ' + profile_data_info.profile_description)
    print()

    # Get a specific profile
    profile_data = profile_client.get_profile('caUserCert')
    print('Profile Data for caUserCert:')
    print('----------------------------')
    print('  Profile ID: ' + profile_data.profile_id)
    print('  Profile Name: ' + profile_data.name)
    print('  Profile Description: ' + profile_data.description)
    print('  Is profile enabled? ' + str(profile_data.enabled))
    print('  Is profile visible? ' + str(profile_data.visible))
    print()

    # Disabling a profile
    print('Disabling a profile:')
    print('--------------------')
    profile_client.disable_profile('caUserCert')
    profile = profile_client.get_profile('caUserCert')
    print('  Profile ID: ' + profile.profile_id)
    print('  Is profile enabled? ' + str(profile.enabled))
    print()

    # Disabling a profile
    print('Enabling a profile:')
    print('-------------------')
    profile_client.enable_profile('caUserCert')
    profile = profile_client.get_profile('caUserCert')
    print('  Profile ID: ' + profile_data.profile_id)
    print('  Is profile enabled? ' + str(profile.enabled))
    print()
    # profile_client.delete_profile('MySampleProfile')
    # Create a new sample profile
    print('Creating a new profile:')
    print('-----------------------')

    profile_data = Profile(name="My Sample User Cert Enrollment",
                           profile_id="MySampleProfile",
                           class_id="caEnrollImpl",
                           description="Example User Cert Enroll Impl",
                           enabled_by='admin', enabled=False, visible=False,
                           renewal=False, xml_output=False,
                           authorization_acl="")

    # Adding a profile input
    profile_input = ProfileInput("i1", "subjectNameInputImpl")
    profile_input.add_attribute(ProfileAttribute("sn_uid"))
    profile_input.add_attribute(ProfileAttribute("sn_e"))
    profile_input.add_attribute(ProfileAttribute("sn_c"))
    profile_input.add_attribute(ProfileAttribute("sn_ou"))
    profile_input.add_attribute(ProfileAttribute("sn_ou1"))
    profile_input.add_attribute(ProfileAttribute("sn_ou2"))
    profile_input.add_attribute(ProfileAttribute("sn_ou3"))
    profile_input.add_attribute(ProfileAttribute("sn_cn"))
    profile_input.add_attribute(ProfileAttribute("sn_o"))

    profile_data.add_input(profile_input)

    # Adding a profile output
    profile_output = ProfileOutput("o1", name="Certificate Output",
                                   class_id="certOutputImpl")
    profile_output.add_attribute(ProfileAttribute("pretty_cert"))
    profile_output.add_attribute(ProfileAttribute("b64_cert"))

    profile_data.add_output(profile_output)

    # Create a Policy set with a list of profile policies
    policy_list = []

    # Creating profile policy
    policy_default = PolicyDefault("Subject Name Default",
                                   "userSubjectNameDefaultImpl",
                                   "This default populates a User-Supplied "
                                   "Certificate Subject Name to the request.")

    attr_descriptor = Descriptor(syntax="string", description="Subject Name")
    policy_attribute = ProfileAttribute("name", descriptor=attr_descriptor)
    policy_default.add_attribute(policy_attribute)

    policy_constraint = PolicyConstraint("Subject Name Constraint",
                                         "This constraint accepts the subject "
                                         "name that matches UID=.*",
                                         "subjectNameConstraintImpl")
    constraint_descriptor = Descriptor(syntax="string",
                                       description="Subject Name Pattern")
    policy_constraint_value = PolicyConstraintValue("pattern",
                                                    "UID=.*",
                                                    constraint_descriptor)
    policy_constraint.add_constraint_value(policy_constraint_value)

    policy_list.append(ProfilePolicy("1", policy_default, policy_constraint))

    # Creating another profile policy
    # Defining the policy default
    policy_default = PolicyDefault("Validity Default", "validityDefaultImpl",
                                   "This default populates a Certificate "
                                   "Validity to the request. The default "
                                   "values are Range=180 in days")
    attr_descriptor = Descriptor(syntax="string", description="Not Before")
    policy_attribute = ProfileAttribute(
        "notBefore",
        descriptor=attr_descriptor)
    policy_default.add_attribute(policy_attribute)

    attr_descriptor = Descriptor(syntax="string", description="Not After")
    policy_attribute = ProfileAttribute("notAfter", descriptor=attr_descriptor)
    policy_default.add_attribute(policy_attribute)

    profile_param = ProfileParameter("range", 180)
    profile_param2 = ProfileParameter("startTime", 0)
    policy_default.add_parameter(profile_param)
    policy_default.add_parameter(profile_param2)

    # Defining the policy constraint
    policy_constraint = PolicyConstraint("Validity Constraint",
                                         "This constraint rejects the validity "
                                         "that is not between 365 days.",
                                         "validityConstraintImpl")
    constraint_descriptor = Descriptor(syntax="integer",
                                       description="Validity Range (in days)",
                                       default_value=365)
    policy_constraint_value = PolicyConstraintValue("range", 365,
                                                    constraint_descriptor)
    policy_constraint.add_constraint_value(policy_constraint_value)

    constraint_descriptor = Descriptor(syntax="boolean", default_value=False,
                                       description="Check Not Before against"
                                                   " current time")
    policy_constraint_value = PolicyConstraintValue("notBeforeCheck", False,
                                                    constraint_descriptor)
    policy_constraint.add_constraint_value(policy_constraint_value)

    constraint_descriptor = Descriptor(syntax="boolean", default_value=False,
                                       description="Check Not After against"
                                                   " Not Before")
    policy_constraint_value = PolicyConstraintValue("notAfterCheck", False,
                                                    constraint_descriptor)
    policy_constraint.add_constraint_value(policy_constraint_value)

    policy_list.append(ProfilePolicy("2", policy_default, policy_constraint))

    policy_set = PolicySet("userCertSet", policy_list)

    profile_data.add_policy_set(policy_set)

    # Write the profile data object to a file for testing a file input
    with open(file_path + '/original.json', 'w') as output_file:
        output_file.write(json.dumps(profile_data,
                                     cls=encoder.CustomTypeEncoder,
                                     sort_keys=True, indent=4))
    # Create a new profile
    created_profile = profile_client.create_profile(profile_data)
    print(created_profile)
    print()

    # Test creating a new profile with a duplicate profile id
    print("Create a profile with duplicate profile id.")
    print("-------------------------------------------")

    try:
        profile_data = Profile(name="My Sample User Cert Enrollment",
                               profile_id="MySampleProfile",
                               class_id="caEnrollImpl",
                               description="Example User Cert Enroll Impl",
                               enabled_by='admin', enabled=False, visible=False,
                               renewal=False, xml_output=False,
                               authorization_acl="")
        profile_input = ProfileInput("i1", "subjectNameInputImpl")
        profile_input.add_attribute(ProfileAttribute("sn_uid"))
        profile_input.add_attribute(ProfileAttribute("sn_e"))
        profile_input.add_attribute(ProfileAttribute("sn_c"))
        profile_input.add_attribute(ProfileAttribute("sn_ou"))
        profile_input.add_attribute(ProfileAttribute("sn_ou1"))
        profile_input.add_attribute(ProfileAttribute("sn_ou2"))
        profile_input.add_attribute(ProfileAttribute("sn_ou3"))
        profile_input.add_attribute(ProfileAttribute("sn_cn"))
        profile_input.add_attribute(ProfileAttribute("sn_o"))

        profile_data.add_input(profile_input)
        profile_client.create_profile(profile_data)
    # pylint: disable=W0703
    except pki.BadRequestException as e:
        print('MySampleProfile ' + str(e))
    print()

    # Modify the above created profile
    print('Modifying the profile MySampleProfile.')
    print('-----------------------------------')

    fetch = profile_client.get_profile('MySampleProfile')
    profile_input2 = ProfileInput("i2", "keyGenInputImpl")
    profile_input2.add_attribute(ProfileAttribute("cert_request_type"))
    profile_input2.add_attribute(ProfileAttribute("cert_request"))
    fetch.add_input(profile_input2)

    fetch.name += " (Modified)"
    modified_profile = profile_client.modify_profile(fetch)

    with open(file_path + 'modified.json', 'w') as output_file:
        output_file.write(json.dumps(fetch, cls=encoder.CustomTypeEncoder,
                                     sort_keys=True, indent=4))

    print(modified_profile)
    print()

    # Delete a profile
    print("Deleting the profile MySampleProfile.")
    print("----------------------------------")
    profile_client.delete_profile('MySampleProfile')
    print("Deleted profile MySampleProfile.")
    print()

    # Testing deletion of a profile
    print('Test profile deletion.')
    print('----------------------')
    try:
        profile_client.get_profile('MySampleProfile')
    # pylint: disable=W0703
    except pki.ProfileNotFoundException as e:
        print(str(e))
    print()

    # Creating a profile from file
    print('Creating a profile using file input.')
    print('------------------------------------')
    original = profile_client.create_profile_from_file(
        file_path + 'original.json')
    print(original)
    print()

    # Modifying a profile from file
    print('Modifying a profile using file input.')
    print('------------------------------------')
    modified = profile_client.modify_profile_from_file(
        file_path + 'modified.json')
    print(modified)
    print()

    # Test clean up
    profile_client.delete_profile('MySampleProfile')
    os.remove(file_path + 'original.json')
    os.remove(file_path + 'modified.json')
    os.removedirs(file_path)


if __name__ == "__main__":
    main()
