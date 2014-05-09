#!/usr/bin/python
"""
Created on May 13,, 2014

@author: akoneru
"""

import types

import pki


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
