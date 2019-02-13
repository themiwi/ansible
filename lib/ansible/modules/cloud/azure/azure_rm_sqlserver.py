#!/usr/bin/python
#
# Copyright (c) 2017 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: azure_rm_sqlserver
version_added: "2.5"
short_description: Manage SQL Server instance
description:
    - Create, update and delete instance of SQL Server

options:
    resource_group:
        description:
            - The name of the resource group that contains the resource. You can obtain this value from the Azure Resource Manager API or the portal.
        required: True
    name:
        description:
            - The name of the server.
        required: True
    location:
        description:
            - Resource location.
    admin_username:
        description:
            - Administrator username for the server. Once created it cannot be changed.
    admin_password:
        description:
            - The administrator login password (required for server creation).
    version:
        description:
            - "The version of the server. For example '12.0'."
    identity:
        description:
            - "The identity type. Set this to 'SystemAssigned' in order to automatically create and assign an Azure Active Directory principal for the resour
               ce. Possible values include: 'SystemAssigned'"
    state:
        description:
            - Assert the state of the SQL server. Use 'present' to create or update a server and
              'absent' to delete a server.
        default: present
        choices:
            - absent
            - present
    purge_vnet_rules:
        description:
            - Remove any existing vnet rules not matching those defined in the vnet_rules parameters.
        type: bool
        default: 'no'
    vnet_rules:
        description:
            - The specified vnets/subnets that will have access to all databases on this server.
        suboptions:
            name:
                description:
                    - Name of the rule.
                required: true
            subnet_name:
                description:
                    - Name or ID of the subnet.
                required: true
                aliases:
                    - subnet
            virtual_network_name:
                description:
                    - Name of the virtual network. This parameter is required
                      if subnet_name is not a resource ID.
                required: False
                aliases:
                    - virtual_network
            resource_group:
                description:
                    - When creating a SQL Server, if a specific subnet from
                      another resource group should be used, use this parameter
                      to specify the resource group to use. Alternatively,
                      specify the full subnet ID in subnet_name.

extends_documentation_fragment:
    - azure
    - azure_tags

author:
    - "Zim Kalinowski (@zikalino)"

'''

EXAMPLES = '''
  - name: Create (or update) SQL Server
    azure_rm_sqlserver:
      resource_group: resource_group
      name: server_name
      location: westus
      admin_username: mylogin
      admin_password: Testpasswordxyz12!
      vnet_rules:
        - name: vnetrule01
          resource_group: other_resource_group
          virtual_network: vn01
          subnet: sn01
'''

RETURN = '''
id:
    description:
        - Resource ID.
    returned: always
    type: str
    sample: /subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/sqlcrudtest-7398/providers/Microsoft.Sql/servers/sqlcrudtest-4645
version:
    description:
        - The version of the server.
    returned: always
    type: str
    sample: 12.0
state:
    description:
        - The state of the server.
    returned: always
    type: str
    sample: state
fully_qualified_domain_name:
    description:
        - The fully qualified domain name of the server.
    returned: always
    type: str
    sample: sqlcrudtest-4645.database.windows.net
vnet_rules:
    description:
        - Deserialized vnet rule instance state dictionaries
    returned: always
    type: list
    sample: [{
        'id': '/subscriptions/d7b6a15c-ac12-4c34-bfd6-017db36407c5/resourceGroups/resource_group/providers/Microsoft.Sql/servers/server_name/virtualNetworkRules/vnetrule01',
        'name': 'vnetrule01',
        'type': 'Microsoft.Sql/servers/virtualNetworkRules',
        'virtual_network_subnet_id': '/subscriptions/8511be51-73da-458b-9f51-08b4a1892dc6/resourceGroups/other_resource_group/providers/Microsoft.Network/virtualNetworks/vn01/subnets/sn01'}]
purged_vnet_rules:
    description:
        - Deserialized instance state dictionaries of the purged vnet rule.
    returned: always
    type: list
    sample: [{
        'id': '/subscriptions/d7b6a15c-ac12-4c34-bfd6-017db36407c5/resourceGroups/resource_group/providers/Microsoft.Sql/servers/server_name/virtualNetworkRules/vnetrule02',
        'name': 'vnetrule01',
        'type': 'Microsoft.Sql/servers/virtualNetworkRules',
        'virtual_network_subnet_id': '/subscriptions/8511be51-73da-458b-9f51-08b4a1892dc6/resourceGroups/other_resource_group/providers/Microsoft.Network/virtualNetworks/vn01/subnets/sn02'}]
'''

import time
from ansible.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from msrestazure.azure_exceptions import CloudError
    from msrestazure.azure_operation import AzureOperationPoller
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from msrest.serialization import Model
    from msrestazure.tools import is_valid_resource_id
except ImportError:
    # This is handled in azure_rm_common
    pass


class Actions:
    NoAction, Create, Update, Delete = range(4)

rule_spec = dict(
    name=dict(type='str', required=True),
    subnet_name=dict(type='str', required=True, aliases=['subnet']),
    virtual_network_name=dict(type='str', aliases=['virtual_network']),
    resource_group=dict(type='str')
    )

class AzureRMServers(AzureRMModuleBase):
    """Configuration class for an Azure RM SQL Server resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
                required=True
            ),
            location=dict(
                type='str',
                required=False
            ),
            admin_username=dict(
                type='str',
                required=False
            ),
            admin_password=dict(
                type='str',
                no_log=True,
                required=False
            ),
            version=dict(
                type='str',
                required=False
            ),
            identity=dict(
                type='str',
                required=False
            ),
            state=dict(
                type='str',
                required=False,
                default='present',
                choices=['present', 'absent']
            ),
            purge_vnet_rules=dict(type='bool', default=False),
            vnet_rules=dict(type='list', elements='dict', options=rule_spec)
        )

        self.resource_group = None
        self.name = None
        self.parameters = dict()

        self.results = dict(changed=False)
        self.mgmt_client = None
        self.state = None
        self.purge_vnet_rules = None
        self.vnet_rules = None
        self.to_do = Actions.NoAction

        super(AzureRMServers, self).__init__(derived_arg_spec=self.module_arg_spec,
                                             supports_check_mode=True,
                                             supports_tags=True)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()) + ['tags']:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                if key == "location":
                    self.parameters.update({"location": kwargs[key]})
                elif key == "admin_username":
                    self.parameters.update({"administrator_login": kwargs[key]})
                elif key == "admin_password":
                    self.parameters.update({"administrator_login_password": kwargs[key]})
                elif key == "version":
                    self.parameters.update({"version": kwargs[key]})
                elif key == "identity":
                    self.parameters.update({"identity": {"type": kwargs[key]}})

        old_response = None
        old_vnet_responses = []
        response = None
        results = dict()

        self.mgmt_client = self.get_mgmt_svc_client(SqlManagementClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager)

        resource_group = self.get_resource_group(self.resource_group)

        if "location" not in self.parameters:
            self.parameters["location"] = resource_group.location

        old_response = self.get_sqlserver()

        if not old_response:
            self.log("SQL Server instance doesn't exist")
            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                self.to_do = Actions.Create
        else:
            self.log("SQL Server instance already exists")
            if self.state == 'absent':
                self.to_do = Actions.Delete
            elif self.state == 'present':
                self.log("Need to check if SQL Server instance has to be deleted or may be updated")
                self.to_do = Actions.Update

        old_vnet_responses = {}
        if old_response:
            old_vnet_responses = self.list_vnet_rules()

        vnet_responses = []
        vnet_rules_to_purge = []

        if (self.to_do == Actions.Create) or (self.to_do == Actions.Update):
            self.log("Need to Create / Update the SQL Server instance")

            if old_response and self.purge_vnet_rules:
                self.log("Checking for existing vnet rules to purge")
                new_rules = {r["name"]: r for r in self.vnet_rules}
                for rule in old_vnet_responses.keys():
                    if rule not in new_rules:
                        self.log("Existing vnet-rule {0} does not exist in parameter vnet_rules. It will be purged".format(rule))
                        vnet_rules_to_purge.append(old_vnet_responses[rule])

            if self.check_mode:
                self.results['changed'] = True
                return self.results

            response = self.create_update_sqlserver()
            response.pop('administrator_login_password', None)

            # purge old vnet rules
            if self.purge_vnet_rules and vnet_rules_to_purge:
                for r in vnet_rules_to_purge:
                    self.delete_vnet_rule(r["name"])
                self.results['changed'] = True

            if self.vnet_rules:
                for r in self.create_update_vnet_rules():
                    self.log('Check whether vnet rule {0} has changed', r['name'])
                    ext_vnet_resp = old_vnet_responses.get(r['name'])
                    if ext_vnet_resp is None or ext_vnet_resp.__ne__(r):
                        self.results['changed'] = True
                    vnet_responses.append(r)

            if not old_response:
                self.results['changed'] = True
            else:
                self.results['changed'] = old_response.__ne__(response)
            self.log("Creation / Update done")
        elif self.to_do == Actions.Delete:
            self.log("SQL Server instance deleted")
            self.results['changed'] = True

            if self.check_mode:
                return self.results

            self.delete_sqlserver()
            # make sure instance is actually deleted, for some Azure resources, instance is hanging around
            # for some time after deletion -- this should be really fixed in Azure
            while self.get_sqlserver():
                time.sleep(20)
        else:
            self.log("SQL Server instance unchanged")
            self.results['changed'] = False
            response = old_response
            vnet_responses = list(old_vnet_responses.values())

        if response:
            self.results["id"] = response["id"]
            self.results["version"] = response["version"]
            self.results["state"] = response["state"]
            self.results["fully_qualified_domain_name"] = response["fully_qualified_domain_name"]
        self.results["vnet_rules"] = vnet_responses
        self.results["purged_vnet_rules"] = vnet_rules_to_purge

        return self.results

    def create_update_sqlserver(self):
        '''
        Creates or updates SQL Server with the specified configuration.

        :return: deserialized SQL Server instance state dictionary
        '''
        self.log("Creating / Updating the SQL Server instance {0}".format(self.name))

        try:
            response = self.mgmt_client.servers.create_or_update(self.resource_group,
                                                                 self.name,
                                                                 self.parameters)
            if isinstance(response, AzureOperationPoller):
                response = self.get_poller_result(response)

        except CloudError as exc:
            self.log('Error attempting to create the SQL Server instance.')
            self.fail("Error creating the SQL Server instance: {0}".format(str(exc)))
        return response.as_dict()

    def delete_sqlserver(self):
        '''
        Deletes specified SQL Server instance in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the SQL Server instance {0}".format(self.name))
        try:
            response = self.mgmt_client.servers.delete(self.resource_group,
                                                       self.name)
        except CloudError as e:
            self.log('Error attempting to delete the SQL Server instance.')
            self.fail("Error deleting the SQL Server instance: {0}".format(str(e)))

        return True

    def get_sqlserver(self):
        '''
        Gets the properties of the specified SQL Server.

        :return: deserialized SQL Server instance state dictionary
        '''
        self.log("Checking if the SQL Server instance {0} is present".format(self.name))
        found = False
        try:
            response = self.mgmt_client.servers.get(self.resource_group,
                                                    self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("SQL Server instance : {0} found".format(response.name))
        except CloudError as e:
            self.log('Did not find the SQL Server instance.')
        if found is True:
            return response.as_dict()

        return False

    def list_vnet_rules(self):
        '''
        Gets the vnet rules of the specified SQL Seerver.

        :return: dict mapping rule names to deserialized vnet rule state dictionaries
        '''
        self.log("Listing the vnet rules for the SQL Server instance {0}".format(self.name))
        found = False
        try:
            response = self.mgmt_client.virtual_network_rules.list_by_server(self.resource_group,
                                                                             self.name)
            found = True
            self.log("Response: {0}".format(response))
        except CloudError as e:
            self.fail("Failure to list vnet rule instances - {0}".format(str(e)))
        if found is True:
            return {r.name: r.as_dict() for r in response}

        return False

    def delete_vnet_rule(self, rule_name):
        '''
        Deletes the named vnet rule of the specified SQL Seerver.

        :return: dict mapping rule names to deserialized vnet rule state dictionaries
        '''
        self.log("Deleting the vnet rule {0} for the SQL Server instance {1}".format(rule_name, self.name))
        response = None
        try:
            response = self.mgmt_client.virtual_network_rules.delete(self.resource_group,
                                                                     self.name,
                                                                     rule_name)
            if isinstance(response, AzureOperationPoller):
                response = self.get_poller_result(response)
            self.log("Response: {0}".format(response))
        except CloudError as e:
            self.fail("Failure to delete vnet rule {0} - {1}".format(rule_name, str(e)))
        # TODO attempting to delete a non-existing vnet rule results in a
        # msrest.exceptions.ClientRequestError caused by  ResponseError('too
        # many 500 error responses',). Presumably this is a bug in Azure, so
        # I won't be trying to handle that here. Also, azure-cli doesn't handle
        # this properly.
        return response

    def create_update_vnet_rules(self):
        '''
        Creates or updates the vnet rules for the SQL Server with the specified configuration.

        :return: generator of deserialized SQL Server vnet rule instance state dictionary
        '''
        net_client = self.network_client
        for rule in self.vnet_rules:
            try:
                self.log("Creating / Updating the vnet rule {0} for SQL Server instance {1}".format(rule['name'],
                                                                                                    self.name))

                subnet = rule['subnet_name']
                if not is_valid_resource_id(subnet):
                    rg = rule['resource_group'] or self.resource_group
                    subnet = net_client.subnets.get(rg, rule['virtual_network_name'], subnet).id
                response = self.mgmt_client.virtual_network_rules.create_or_update(self.resource_group,
                                                                                   self.name,
                                                                                   rule['name'],
                                                                                   subnet
                                                                                   )
                if isinstance(response, AzureOperationPoller):
                    response = self.get_poller_result(response)

            except CloudError as exc:
                self.fail('Error creating or updating the vnet rule {0}: {1}'.format(rule['name'],
                                                                                     str(exc)))
            yield response.as_dict()



def main():
    """Main execution"""
    AzureRMServers()


if __name__ == '__main__':
    main()
