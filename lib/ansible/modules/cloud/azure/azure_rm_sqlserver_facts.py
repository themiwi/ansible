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
module: azure_rm_sqlserver_facts
version_added: "2.5"
short_description: Get SQL Server facts.
description:
    - Get facts of SQL Server.

options:
    resource_group:
        description:
            - The name of the resource group that contains the resource. You can obtain this value from the Azure Resource Manager API or the portal.
        required: True
    server_name:
        description:
            - The name of the server.

extends_documentation_fragment:
    - azure
    - azure_tags

author:
    - "Zim Kalinowski (@zikalino)"

'''

EXAMPLES = '''
  - name: Get instance of SQL Server
    azure_rm_sqlserver_facts:
      resource_group: resource_group_name
      server_name: server_name

  - name: List instances of SQL Server
    azure_rm_sqlserver_facts:
      resource_group: resource_group_name
'''

RETURN = '''
servers:
    description: A list of dict results where the key is the name of the SQL Server and the values are the facts for that SQL Server.
    returned: always
    type: complex
    contains:
        sqlserver_name:
            description: The key is the name of the server that the values relate to.
            type: complex
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: /subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/sqlcrudtest-7398/providers/Microsoft.Sql/servers/sqlcrudtest-4645
                name:
                    description:
                        - Resource name.
                    returned: always
                    type: str
                    sample: sqlcrudtest-4645
                type:
                    description:
                        - Resource type.
                    returned: always
                    type: str
                    sample: Microsoft.Sql/servers
                location:
                    description:
                        - Resource location.
                    returned: always
                    type: str
                    sample: japaneast
                kind:
                    description:
                        - Kind of sql server. This is metadata used for the Azure portal experience.
                    returned: always
                    type: str
                    sample: v12.0
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
                    sample: Ready
                fully_qualified_domain_name:
                    description:
                        - The fully qualified domain name of the server.
                    returned: always
                    type: str
                    sample: fully_qualified_domain_name
                vnet_rules:
                    description:
                        - A list of deserialized vnet rule state dictionaries.
                    returned: always
                    type: list
                    sample: [{
                        'id': '/subscriptions/d7b6a15c-ac12-4c34-bfd6-017db36407c5/resourceGroups/resource_group/providers/Microsoft.Sql/servers/server_name/virtualNetworkRules/vnetrule02',
                        'name': 'vnetrule01',
                        'type': 'Microsoft.Sql/servers/virtualNetworkRules',
                        'virtual_network_subnet_id': '/subscriptions/8511be51-73da-458b-9f51-08b4a1892dc6/resourceGroups/other_resource_group/providers/Microsoft.Network/virtualNetworks/vn01/subnets/sn02'}]
'''

from ansible.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from msrestazure.azure_exceptions import CloudError
    from msrestazure.azure_operation import AzureOperationPoller
    from azure.mgmt.sql import SqlManagementClient
    from msrest.serialization import Model
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMServersFacts(AzureRMModuleBase):
    def __init__(self):
        # define user inputs into argument
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            server_name=dict(
                type='str'
            )
        )
        # store the results of the module operation
        self.results = dict(
            changed=False,
            ansible_facts=dict()
        )
        self.mgmt_client = None
        self.resource_group = None
        self.server_name = None
        super(AzureRMServersFacts, self).__init__(self.module_arg_spec)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])
        self.mgmt_client = self.get_mgmt_svc_client(SqlManagementClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager)

        if (self.resource_group is not None and
                self.server_name is not None):
            self.results['servers'] = self.get()
        elif (self.resource_group is not None):
            self.results['servers'] = self.list_by_resource_group()
        return self.results

    def get(self):
        '''
        Gets facts of the specified SQL Server.

        :return: deserialized SQL Serverinstance state dictionary
        '''
        response = None
        results = {}
        try:
            response = self.mgmt_client.servers.get(resource_group_name=self.resource_group,
                                                    server_name=self.server_name)
            self.log("Response for SQL server : {0}".format(response))
        except CloudError as e:
            self.log('Could not get facts for Servers.')

        if response is not None and vnet_responses is not None:
            results[response.name] = response.as_dict()
            results[repsonse.name]['vnet_rules'] = [r.as_dict() for r in vnet_responses]

        return results

    def list_by_resource_group(self):
        '''
        Gets facts of the specified SQL Server.

        :return: deserialized SQL Server instance state dictionary
        '''
        response = None
        results = {}
        try:
            response = self.mgmt_client.servers.list_by_resource_group(resource_group_name=self.resource_group)
            self.log("Response : {0}".format(response))
        except CloudError as e:
            self.log('Could not get facts for Servers.')

        if response is not None:
            for item in response:
                results[item.name] = item.as_dict()

        return results

    def get_vnet_rules(self, server_name):
        '''
        Gets facts about the vnet rules for the specified SQL Server.

        :return: list of deserialized vnet rule instance state dictionaries
        '''
        responses = None
        results = []
        try:
            responses = self.mgmt_client.virtual_network_rules.list_by_server(self.resource_group,
                                                                              server_name)
            self.log("Response for vnet rules : {0}".format(responses))
        except CloudError as e:
            self.log('Could not get facts for vnet rules of server {0}.', server_name)

        if responses is not None:
            results = [r.as_dict() for r in responses]

        return results


def main():
    AzureRMServersFacts()


if __name__ == '__main__':
    main()
