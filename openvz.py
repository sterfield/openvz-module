#!/usr/bin/python
import json
import re
import os.path

DOCUMENTATION = '''
---
module: openvz
short_description: Create / update / delete OpenVZ containers
description:
    - Using this module, you can create, update and delete containers.
version_added: "1.0"
author: Guillaume Loetscher
requirements:
    - a recent OpenVZ kernel
    - vzctl & vzlist command
options:
    veid:
        description:
            - This is the ID for the OpenVZ container
        required: true
    name:
        description:
            - Name of the container
        required: false
    hostname:
        description:
            - Hostname of the container
        required: false
    diskspace:
        description:
            - Size of the disk for the container.
            - You can use a value in bytes or a value using units such as
            -  B, K, M, G, T or P (lowercase are also supported)
            - You can also provide a integer value, but in this case, the 
            - value is in KiB (Kibibytes)
        required: false
    ram:
        description:
            - Size of the ram for the container.
            - You can use a value in bytes or a value using units such as
            -  B, K, M, G, T or P (lowercase are also supported)
            - You can also provide a integer value, but in this case, the 
            - value is in bytes.
        required: false
    swap:
        description:
            - Size of the swap for the container.
            - You can use a value in bytes or a value using units such as
            -  B, K, M, G, T or P (lowercase are also supported)
            - You can also provide a integer value, but in this case, the 
            - value is in bytes.
        required: false
    ostemplate:
        description:
            - Template used to create the container.
            -  This template must be installed on your hypervisor, or it will
            -  failed
        required: false
    ips:
        description:
            - You can set one or several IPs in this field. You can either
            - set the IP directly as a string, or several IPs using a list.
            - The module will automatically add or remove IPs according to
            - the information you'll provide.
            - Please see the example section.
        required: false
    onboot:
        description:
            - If the container will automatically start at the boot of the
            - hypervisor.
        choices: ['on', 'yes', True, 'off', 'no', False]
        required: false
    nameserver:
        description:
            - Set one or multiple nameserver on the container. You can provide
            - either a single string as a nameserver, or a list of nameserver.
            - Please see the example section.
        required: false
    searchdomain:
        description:
            - Set one or multiple search domains on the container. You can
            - provide either a single string as a search domain, or a list of
            - search domains. Please see the example section.
        required: false
'''

EXAMPLES = '''
# Create or update a container, ID 123
- openvz:
    veid: 123
    state: present

# Delete a container ID 123
- openvz:
    veid: 123
    state: absent

# Set a single nameserver, search domain and IP on the container 123
- openvz:
    veid: 123
    state: present
    nameserver: "172.16.0.1"
    searchdomain : "example.com"
    ips: "172.16.10.100"

# Set multiple nameserver, search domains and IPs on the container 123
- openvz:
    veid: 123
    state: present
    nameserver:
        - "172.16.0.1"
        - "172.16.0.2"
    searchdomain:
        - "example.com"
        - "inside.example.com"
    ips:
        - "172.16.10.100"
        - "172.16.10.101"

# Update a diskspace to 20 GB, ram to 2GB and swap to 500 MB
- openvz
    veid: 123
    state: present
    diskspace: 20G
    ram: 2G
    swap: 500000000
'''

VZ_CONF_FOLDER = '/etc/vz/conf/'


class OpenVZ():

    def __init__(self, module):
        self.module = module
        self.changed = False
        self.veid = module.params.get('veid')
        self.name = module.params.get('name')
        self.hostname = module.params.get('hostname')
        self.ostemplate = module.params.get('ostemplate')
        self.diskspace = module.params.get('diskspace')
        self.ips = module.params.get('ips')
        self.nameserver = module.params.get('nameserver')
        self.onboot = module.params.get('onboot')
        self.ram = module.params.get('ram')
        self.swap = module.params.get('swap')
        self.searchdomain = module.params.get('searchdomain')

        # Verifying that the VEID given is OK
        self.check_veid()
        if self.diskspace:
            self.diskspace = OpenVZ.convert_space_unit(self.diskspace)
            self.diskspace /= 1024 # because the size of the option diskspace
            # is in KB, not bytes.
        if self.ram:
            self.ram = OpenVZ.convert_space_unit(self.ram)
            self.ram = OpenVZ.convert_pages(self.ram)
        if self.swap:
            self.swap = OpenVZ.convert_space_unit(self.swap)
            self.swap = OpenVZ.convert_pages(self.swap)
        if self.ips:
            self.ips = OpenVZ.convert_to_list(self.ips)
        if self.nameserver:
            self.nameserver = OpenVZ.convert_to_list(self.nameserver)
        if self.searchdomain:
            self.searchdomain = OpenVZ.convert_to_list(self.searchdomain)

    @staticmethod
    def convert_to_list(value):
        """Get the value that could be a list or a string.
        If it's a string, put it into a list, and return it."""
        if type(value) is not list:
            result = []
            result.append(value)
            return result
        else:
            return value

    @staticmethod
    def convert_pages(value):
        """Take a value in bytes , and convert it to memory
        pages (in Linux, by default, page = 4096 bytes."""
        try:
            value = int(value)
        except TypeError:
            self.module.fail_json(
                msg="You haven't provide an integer as ram / swap size"""
            )
        if value % 4096 == 0:
            return value / 4096
        else:
            return (value / 4096) + 1

    @staticmethod
    def convert_space_unit(value_w_suffix):
        """Take the space given in arguement. If there's a suffix (G, T, etc..),
        convert the space in bytes. If the value is already an int, then
        there's no conversion to do. Therefore returning the value
        """
        if type(value_w_suffix) is int:
            result = value_w_suffix
        else:
            try:
                suffix = value_w_suffix[-1].lower()
                value = int(value_w_suffix[:-1])
            except (TypeError, IndexError):
                self.module.fail_json(
                    msg="The space unit you have entered is apparently"
                        " incorrect. Please provide an unit as described"
                        " in vzctl manual"
                )
            if suffix == 'b':
                result = value
            elif suffix == 'k':
                result = value * 1024
            elif suffix == 'm':
                result = value * 1024 * 1024
            elif suffix == 'g':
                result = value * 1024 * 1024 * 1024
            elif suffix == 't':
                result = value * 1024 * 1024 * 1024 * 1024
            elif suffix == 'p':
                result = value * 1024 * 1024 * 1024 * 1024 * 1024
        return result

    def check_veid(self):
        if type(self.veid) is not int:
            try:
                veid = int(self.veid)
            except ValueError:
                self.module.fail_json(msg="You haven't provided a valid "
                                          "integer as an OpenVZ ID")
            else:
                self.veid = veid

    def get_veid_list(self):
        """Get the list of VZ ID installed on the Hypervisor"""
        command_line = 'vzlist -a1j'
        rc, stdout, stderr = self.module.run_command(command_line)
        if rc != 0:
            self.module.fail_json(msg="vzlist is not installed or failed to be"
                                      " executed properly.")
        veid_list = json.loads(stdout)
        # vzlist -1aj is returning a JSON list of dict, containing only the key
        # 'veid' and the value, for each vz installed on the hypervisor
        return [veid['veid'] for veid in veid_list]

    def get_configuration(self):
        """Get the configuration of only one container if veid is set.
        If veid set to None, get the configuration of all the containers.
        """
        command = 'vzlist -aj {}'.format(self.veid)
        rc, stdout, stderr = self.module.run_command(command)
        if rc != 0:
            self.module.fail_json(
                msg="vzlist is not installed or failed to be executed properly"
            )
        else:
            # There's only one dict corresponding at the current container
            # so extracting the first item to get only the map
            config_map = json.loads(stdout)[0]

        if config_map['layout'] == 'ploop':
            try:
                config_file_name = "{}.conf".format(self.veid)
                config_abs_path = os.path.join(
                    VZ_CONF_FOLDER,
                    config_file_name
                )
                with open(config_abs_path, 'r') as fd:
                    regex = re.compile('^\s*DISKSPACE\s*=\s*"(\d+):(\d+)"\s*$')
                    for line in fd:
                        result = regex.match(line)
                        if result:
                            break
                    else:
                        self.module.fail_json(
                            msg="Cannot retrieve the DISKSPACE value in the"
                                " configuration file"
                        )
            except (OSError, IOError):
                self.module.fail_json(
                    msg="Cannot open the container configuration file"
                )
            else:
                diskspace_soft = int(result.group(1))
                diskspace_hard = int(result.group(2))
            config_map['diskspace']['softlimit'] = diskspace_soft
            config_map['diskspace']['hardlimit'] = diskspace_hard

        return config_map

    def to_be_updated(self, config_map):
        """Get the configuration of the container currently installed on the
        hypervisor, then check value per value if it needs to be updated or
        not. If so, return a map containing the argument that needs to be
        updated as a key, and a tuple as a value. The tuple contains two
        values : the first is the value before update, the second the value
        after update."""
        changed_map = {}
        if config_map['onboot'] != self.onboot:
            changed_map.update({
                'onboot': (config_map['onboot'], self.onboot)
            })
        if self.name and config_map['name'] != self.name:
            changed_map.update({
                'name': (config_map['name'], self.name)
            })
        if self.hostname and config_map['hostname'] != self.hostname:
            changed_map.update({
                'hostname': (config_map['hostname'], self.hostname)
            })
        if self.ostemplate and config_map['ostemplate'] != self.ostemplate:
            changed_map.update({
                'ostemplate': (config_map['ostemplate'], self.ostemplate)
            })
        config_diskspace = config_map['diskspace']['hardlimit']
        if self.diskspace and config_diskspace != self.diskspace:
            changed_map.update({
                'diskspace': (config_diskspace, self.diskspace)
            })
        if self.ips and self.ips != config_map['ip']:
            changed_map.update({
                'ips': (config_map['ip'], self.ips)
            })
        if self.nameserver and self.nameserver != config_map['nameserver']:
            changed_map.update({
                'nameserver': (config_map['nameserver'], self.nameserver)
            })
        config_ram = config_map['physpages']['limit']
        if self.ram and self.ram != config_ram:
            changed_map.update({
                'ram': (config_ram, self.ram)
            })
        config_swap = config_map['swappages']['limit']
        if self.swap and self.swap != config_swap:
            changed_map.update({
                'swap': (config_swap, self.swap)
            })
        if (self.searchdomain and
           self.searchdomain != config_map['searchdomain']):
            changed_map.update({
                'searchdomain': (config_map['searchdomain'], self.searchdomain)
            })
        return changed_map

    def create_or_update(self):
        """Check if the container already exists. If yes, update it (if
        needed. If no, create it."""
        veid_list = self.get_veid_list()
        if self.veid in veid_list:
            self.update()
        else:
            self.create()

    def update(self):
        config_map = self.get_configuration()
        changed_map = self.to_be_updated(config_map)
        if changed_map:
            self.changed = True
            command_line = "vzctl set {} --save".format(self.veid)
            if 'onboot' in changed_map:
                new_onboot = ('yes' if changed_map['onboot'][1] else 'no')
                command_line += ' --onboot {}'.format(new_onboot)
            if 'name' in changed_map:
                new_name = changed_map['name'][1]
                command_line += ' --name {}'.format(new_name)
            if 'ips' in changed_map:
                new_ips_list = changed_map['ips'][1]
                current_ips_list = changed_map['ips'][0]
                ips_to_add = set(new_ips_list) - set(current_ips_list)
                ips_to_remove = set(current_ips_list) - set(new_ips_list)
                for ip in ips_to_add:
                    command_line += ' --ipadd {}'.format(ip)
                for ip in ips_to_remove:
                    command_line += ' --ipdel {}'.format(ip)
            if 'hostname' in changed_map:
                new_hostname = changed_map['hostname'][1]
                command_line += ' --hostname {}'.format(new_hostname)
            if 'nameserver' in changed_map:
                new_ns_list = changed_map['nameserver'][1]
                for ns in new_ns_list:
                    command_line += ' --nameserver {}'.format(ns)
            if 'diskspace' in changed_map:
                new_diskspace = changed_map['diskspace'][1]
                command_line += ' --diskspace {}'.format(new_diskspace)
            if 'ram' in changed_map:
                new_ram = changed_map['ram'][1]
                command_line += ' --physpages {}'.format(new_ram)
            if 'swap' in changed_map:
                new_swap = changed_map['swap'][1]
                command_line += ' --swappages {}'.format(new_swap)
            if 'searchdomain' in changed_map:
                new_searchdomain_list = changed_map['searchdomain'][1]
                for searchdomain in new_searchdomain_list:
                    command_line += ' --searchdomain {}'.format(searchdomain)

            rc, stdout, stderr = self.module.run_command(command_line)
            if rc != 0:
                self.module.fail_json(
                    msg="Cannot update the configuration"
                        " of container {}.\n"
                        "Full line : {}".format(self.veid, command_line)
                )
            #self.module.fail_json(msg=command_line)
        self.module.exit_json(changed=self.changed)

    def create(self):
        if not self.diskspace:
            self.module.fail_json(msg="You haven't provided any diskspace")

        create_vz_command = (
            'vzctl create {veid} --layout ploop'
            ' --diskspace {diskspace}'
        ).format(
            veid=self.veid,
            diskspace=self.diskspace,
        )
        if self.hostname:
            create_vz_command += ' --hostname {0}'.format(self.hostname)
        if self.name:
            create_vz_command += ' --name {0}'.format(self.name)
        if self.ostemplate:
            create_vz_command += ' --ostemplate {0}'.format(self.ostemplate)
        if self.ips:
            ip_command = ''
            for ip in self.ips:
                ip_command += ' --ipadd {0}'.format(ip)
            create_vz_command += ip_command
        rc, stdout, stderr = self.module.run_command(create_vz_command)
        self.changed = True
        if rc != 0:
            self.module.fail_json(msg="Failed to create the VZ !\n"
                                      "stderr : {0}".format(stderr))
        else:
            self.update()
            self.module.exit_json(
                msg="VZ {} created".format(self.veid),
                changed=self.changed
            )

    def delete(self):
        vz_list = self.get_veid_list()
        if self.veid in vz_list:
            config_map = self.get_configuration()
            if config_map['status'] != 'stopped':
                self.module.fail_json(
                    msg="Cannot destroy the container, it's not stopped !"
                )
            else:
                command = 'vzctl destroy {}'.format(self.veid)
                rc, stdout, stderr = self.module.run_command(command)
                if rc != 0:
                    self.module.fail_json(
                        msg="Cannot destroy the container {}".format(self.veid)
                    )
                else:
                    self.changed = True
        self.module.exit_json(changed=self.changed)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            veid=dict(required=True),
            name=dict(),
            hostname=dict(),
            diskspace=dict(),
            ostemplate=dict(),
            ips=dict(),
            onboot=dict(choices=[True, False]),
            nameserver=dict(),
            searchdomain=dict(),
            ram=dict(),
            swap=dict(),
            state=dict(choices=['present', 'absent'], required=True)
        )
    )

    openvz = OpenVZ(module)
    if module.params['state'] == 'present':
        openvz.create_or_update()
    elif module.params['state'] == 'absent':
        openvz.delete()

from ansible.module_utils.basic import *
main()
