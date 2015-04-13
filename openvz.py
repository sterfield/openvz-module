#!/usr/bin/python
import json
import re


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
    state:
        description:
            - The state of the container you want to acheive.
        choices: ['present', 'absent']
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

# This is the list of variables that are not using "limit" and "barrier"
# but respectively "softlimit" and "hardlimit"
HARDLIMIT_VARS = ('DISKSPACE', 'DISKINODES')
# This is the list of variables that are using "limit" and "barrier"
BARRIER_VARS = ('KMEMSIZE', 'LOCKEDPAGES', 'PRIVVMPAGES', 'SHMPAGES', 'NUMPROC',
                'PHYSPAGES', 'VMGUARPAGES', 'OOMGUARPAGES', 'NUMTCPSOCK',
                'NUMFLOCK', 'NUMPTY', 'NUMSIGINFO', 'TCPSNDBUF', 'TCPRCVBUF',
                'OTHERSOCKBUF', 'DGRAMRCVBUF', 'NUMOTHERSOCK', 'DCACHESIZE',
                'NUMFILE', 'AVNUMPROC', 'NUMIPTENT', 'SWAPPAGES')

MULTIVALUED_VARS = ('IP_ADDRESS', 'NAMESERVER', 'SEARCHDOMAIN')

class OpenVZException(Exception):
    """ This exception will be thrown when there's an issue with the Kernel
    """

    def __init__(self, msg):
        self.msg = msg

class OpenVZKernelException(OpenVZException):
    pass

class OpenVZListException(OpenVZException):
    pass

class OpenVZConfigurationException(OpenVZException):
    pass

class OpenVZ():

    def __init__(self, module):
        self.module = module
        self.changed = False
        self.layout = module.params.get('layout')
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
        self.kernel = {
            'linux_kernel': '',
            'ovz_major_version': -1,
            'ovz_branch': '',
            'ovz_minor_version': -1,
            'ovz_addon_number': -1,
            'architecture': ''
        }
        # Get all information about kernel and verify it's an OpenVZ one
        self.get_kernel_version()

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
        If it's a string, put it into a list, and return it. This function comes
        in handy, as the user is able to provide either lists, or a single
        string as data. For example, he can provide a list of IPS, or a
        single IP.
        """
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
            raise OpenVZConfigurationException("You haven't provide an integer as ram / swap size")
        if value % 4096 == 0:
            return value / 4096
        else:
            return (value / 4096) + 1

    @staticmethod
    def convert_space_unit(value_w_suffix):
        """Take the space given in argument. If there's a suffix (G, T, etc..),
        convert the space in bytes. If the value is already an int, then
        there's no conversion to do. Therefore returning the value
        """
        try:
            result = float(value_w_suffix)
        except (TypeError, ValueError):
            try:
                # Most likely, the user entered a string like "18G". Taking the last
                # character, and catching the rest as a value.
                suffix = value_w_suffix[-1].lower()
                value = float(value_w_suffix[:-1])
            except (TypeError, IndexError):
                raise OpenVZConfigurationException(
                    "The space unit you have entered is apparently"
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
            else:
                raise OpenVZConfigurationException(
                    "The space unit you have entered is apparently"
                    " incorrect. Please provide an unit as described"
                    " in vzctl manual"
                )
        return int(result)

    def get_kernel_version(self):
        """Get the kernel version by calling "uname -r". It will allow to check
        if this is indeed an OpenVZ kernel, and what can be done (for example,
         you cannot do ploop on old OpenVZ kernels"""
        command_line = "uname -r"
        rc, stdout, stderr = self.module.run_command(command_line)
        if rc != 0:
            raise OpenVZKernelException("Cannot get the kernel version.")
        else:
            # Main regexp, just to filter the kernel and be sure it mentionned
            #  openvz
            regexp_kernel = '(?P<kernel>.+)-openvz-(?P<ovz_info>.*)$'
            result = re.match(regexp_kernel, stdout)
            if not result:
                raise OpenVZKernelException(
                    "The current kernel doesn't seems to be an OpenVZ one."
                    "Current kernel : {0}".format(stdout)
                )
            else:
                # It's an OpenVZ kernel, so getting the part after "-openvz-"
                #  string
                ovz_string = result.group('ovz_info')
                linux_kernel = result.group('kernel')
                self.kernel['linux_kernel'] = linux_kernel

                # if the string is equal to "amd64", then it's an old
                #  OpenVZ kernel, issued from Debian 6 repository.
                if ovz_string == "amd64":
                    self.kernel['architecture'] = 'amd64'
                else:
                    # the rest of the uname string is not only "amd64",
                    #  so it's most likely an OpenVZ kernel, issued from OpenVZ
                    #  repositories.
                    # See https://openvz.org/Kernel_versioning for information.

                    regexp_openvz = ('(?P<ovz_major_version>\d{3})'
                                     '(?P<ovz_branch>stab|test)'
                                     '(?P<ovz_minor_version>\d{3})\.'
                                     '(?P<ovz_addon_number>\d)-'
                                     '(?P<architecture>.*)$')
                    result = re.match(regexp_openvz, ovz_string)
                    if result:
                        self.kernel['ovz_major_version'] = int(
                            result.group('ovz_major_version')
                        )
                        self.kernel['ovz_branch'] = result.group('ovz_branch')
                        self.kernel['ovz_minor_version'] = int(
                            result.group('ovz_minor_version')
                        )
                        self.kernel['ovz_addon_number'] = int(
                            result.group('ovz_addon_number')
                        )
                        self.kernel['architecture'] = result.group(
                            'architecture'
                        )
                    else:
                        raise OpenVZKernelException(
                            "Cannot extract OpenVZ information from the kernel."
                            "Is is OpenVZ ? Current kernel : {0}".format(stdout)
                        )

    def verify_ploop_availability(self):
        """Comparing OpenVZ minor_version and major_version, and according to
        the values, return True or False if the kernel can manage ploop
        """
        return (self.kernel['ovz_major_version'] >= 42 and
                self.kernel['ovz_minor_version'] >= 58)

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
            # Cannot get the JSON output from vzlist, trying to get "standard"
            # output.
            command_line = 'vzlist -1a'
            rc, stdout, stderr = self.module.run_command(command_line)
            if rc != 0:
                # The command failed again, raising exception and exiting.
                raise OpenVZListException(
                    "vzlist is not installed or failed to be executed properly."
                    "Stderr : {0}".format(stderr)
                )
            else:
                # We got the list of VEID through "normal" output. Grabing the
                # list of VEID.
                veid_list = [int(veid) for veid in stdout.split()]
        else:
            # We got the list of VEID through JSON output.
            # vzlist -1aj is returning a JSON list of dict, containing only the
            # key 'veid' and the value, for each vz installed on the hypervisor
            veid_json_list = json.loads(stdout)
            veid_list = [veid['veid'] for veid in veid_json_list]

        return veid_list

    def get_vzlist_json_configuration(self):
        """Getting the configuration of a said container using "vzlist -j".
        On some older kernels (OpenVZ from Debian 6 for example), the vzlist doesn't have
        a JSON output, so it'll failed. Returning an empty dict in that case.
        """
        command = 'vzlist -aj {0}'.format(self.veid)
        rc, stdout, stderr = self.module.run_command(command)
        if rc != 0:
            return {}
        else:
            # There's only one dict corresponding at the current container
            # so extracting the first item to get only the map
            config_map = json.loads(stdout)[0]
            return config_map

    @staticmethod
    def extract_variable_information(result_list):
        """Get the list of tuple (<variable>, <value).
        different cases :
          - the value has a format '<soft limit>:<hard limit>'
          - the value is a single string / value
          - the variable is listed as a MULTIVALUED_VARS
        So, returning a dictionary, composed of:
         - the variable name, in lowercase, as the key
         - the value:
            - a string, if the value is just a string
            - a small dictionary, containing "softlimit" and "hardlimit" as keys
              if the variable is listed in HARDLIMIT_VARS
            - a small dictionary, containing "barrier" and "limit" as keys, if
              the variable is not listed in HARDLIMIT_VARS
            - a list of values if the variable is listed as MULTIVALUED_VARS
        """

        config_map = {}
        for variable, value in result_list:
            if ':' in value:
                softlimit, hardlimit = value.split(':')
                if softlimit == 'unlimited':
                    softlimit = 9223372036854775807
                if hardlimit == 'unlimited':
                    hardlimit = 9223372036854775807
                else:
                    # So there's a value, either integer one or a value like
                    # '23G'. So converting those value to integer one, using
                    # convert_space_unit() function
                    softlimit = OpenVZ.convert_space_unit(softlimit)
                    hardlimit = OpenVZ.convert_space_unit(hardlimit)

                if variable in HARDLIMIT_VARS:
                    config_map[variable.lower()] = {
                        'softlimit': softlimit,
                        'hardlimit': hardlimit,
                    }
                elif variable in BARRIER_VARS:
                    config_map[variable.lower()] = {
                        'barrier': softlimit,
                        'limit': hardlimit,
                    }
            else:
                if variable == 'ONBOOT':
                    if value == 'yes':
                        config_map[variable.lower()] = True
                    else:
                        config_map[variable.lower()] = False
                elif variable in MULTIVALUED_VARS:
                    # in old OpenVZ kernel, IPs are stored in variable
                    # "IP_ADDRESS" where in new kernel, they are stored in the
                    # JSON structure in the "ip" key. Using "ip" key as a common
                    # key.
                    if variable == 'IP_ADDRESS':
                        config_map['ip'] = value.split()
                    else:
                        config_map[variable.lower()] = value.split()
                elif variable in BARRIER_VARS:
                    # The variable should be using the format "barrier:limit",
                    # but for unknown reason, sometimes, there's only one value
                    # for the variable. So storing the same value for barrier
                    # and limit.
                    config_map[variable.lower()] = {
                        'barrier': int(value),
                        'limit': int(value),
                    }
                elif variable in HARDLIMIT_VARS:
                    # Same but for "hardlimit" variables
                    config_map[variable.lower()] = {
                        'softlimit': int(value),
                        'hardlimit': int(value),
                    }
                else:
                    # Trying to convert the value in integer. If it fails, then
                    # it's most likely a string, then copy it as it is
                    try:
                        config_map[variable.lower()] = int(value)
                    except (TypeError, ValueError):
                        config_map[variable.lower()] = value
        return config_map



    def get_container_file_configuration(self):
        """Get a container configuration from the configuration file, normally stored in
        /etc/vz/conf/<veid>.conf.
        """
        config_file = '/etc/vz/conf/{0}.conf'.format(self.veid)

        # Creating a regexp catching <variable name>="<value>"
        regexp = '^\s*(?P<variable>\w+)\s*=\s*"(?P<value>[^"]*)"\s*$'
        try:
            with open(config_file, 'r') as fd:
                config_content = fd.read()
        except (OSError, IOError):
            return {}

        result = re.findall(regexp, config_content, re.MULTILINE)
        return OpenVZ.extract_variable_information(result)


    def get_configuration(self):
        """Get the configuration of only one container.
        """
        json_config_map = self.get_vzlist_json_configuration()
        file_config_map = self.get_container_file_configuration()
        if json_config_map:
            json_config_map['diskspace'] = file_config_map['diskspace']
            return json_config_map
        elif file_config_map:
            return file_config_map
        else:
            raise OpenVZConfigurationException(
                "Cannot retrieve information from either vzlist JSON output "
                "or from the configuration file."
            )

    def to_be_updated(self, config_map):
        """Get the configuration of the container currently installed on the
        hypervisor, then check value per value if it needs to be updated or
        not. If so, return a map containing the argument that needs to be
        updated as a key, and a tuple as a value. The tuple contains two
        values : the first is the value before update, the second the value
        after update."""
        changed_map = {}
        if self.onboot and config_map.get('onboot') != self.onboot:
            changed_map['onboot'] = (config_map.get('onboot'), self.onboot)
        if self.name and config_map.get('name') != self.name:
            changed_map['name'] = (config_map.get('name'), self.name)
        if self.hostname and config_map.get('hostname') != self.hostname:
            changed_map['hostname'] = (
                config_map.get('hostname'),
                self.hostname
            )
        try:
            if (self.diskspace and
                    config_map['diskspace']['hardlimit'] != self.diskspace):
                changed_map['diskspace'] = (
                    config_map['diskspace']['hardlimit'],
                    self.diskspace
                )
        except KeyError:
            changed_map['diskspace'] = (None, self.diskspace)
        if self.ips and set(self.ips) != set(config_map.get('ip', [])):
            changed_map['ips'] = (config_map.get('ip', []), self.ips)
        if (self.nameserver and
            set(self.nameserver) != set(
                config_map.get('nameserver', [])
            )):
            changed_map['nameserver'] = (
                config_map.get('nameserver', []),
                self.nameserver
            )
        try:
            if self.ram and self.ram != config_map['physpages']['limit']:
                changed_map['ram'] = (
                    config_map['physpages']['limit'],
                    self.ram
                )
        except KeyError:
            changed_map['ram'] = (None, self.ram)
        try:
            if self.swap and self.swap != config_map['swappages']['limit']:
                changed_map['swappages'] = (
                    config_map['swappages']['limit'],
                    self.swap
                )
        except KeyError:
            changed_map['swappages'] = (None, self.swap)
        if (self.searchdomain and
                set(self.searchdomain) != set(config_map.get('searchdomain',
                                                             []))):
            changed_map['searchdomain'] = (
                config_map.get('searchdomain', []), self.searchdomain
            )
        return changed_map

    def verify_options(self):
        """Take all the options entered by the user, and try to see if there's any error
        If so, raising an OpenVZConfigurationException.
        """
        if not self.verify_ploop_availability() and self.layout == 'ploop':
            raise OpenVZConfigurationException("Your kernel is too old to do ploop")


    def create_or_update(self):
        """Check if the container already exists. If yes, update it (if
        needed. If no, create it."""
        self.verify_options()
        veid_list = self.get_veid_list()
        if self.veid in veid_list:
            self.update()
        else:
            self.create()

    def update(self):
        config_map = self.get_configuration()
        changed_map = self.to_be_updated(config_map)
        if changed_map:
            command_line = "vzctl set {0} --save".format(self.veid)
            if 'onboot' in changed_map:
                new_onboot = ('yes' if changed_map['onboot'][1] else 'no')
                command_line += ' --onboot {0}'.format(new_onboot)
                self.changed = True
            if 'name' in changed_map:
                new_name = changed_map['name'][1]
                command_line += ' --name {0}'.format(new_name)
                self.changed = True
            if 'ips' in changed_map:
                self.changed = True
                new_ips_list = changed_map['ips'][1]
                current_ips_list = changed_map['ips'][0]
                ips_to_add = set(new_ips_list) - set(current_ips_list)
                ips_to_remove = set(current_ips_list) - set(new_ips_list)
                for ip in ips_to_add:
                    command_line += ' --ipadd {0}'.format(ip)
                for ip in ips_to_remove:
                    command_line += ' --ipdel {0}'.format(ip)
            if 'hostname' in changed_map:
                self.changed = True
                new_hostname = changed_map['hostname'][1]
                command_line += ' --hostname {0}'.format(new_hostname)
            if 'nameserver' in changed_map:
                self.changed = True
                new_ns_list = changed_map['nameserver'][1]
                for ns in new_ns_list:
                    command_line += ' --nameserver {0}'.format(ns)
            if 'searchdomain' in changed_map:
                self.changed = True
                new_searchdomain_list = changed_map['searchdomain'][1]
                for searchdomain in new_searchdomain_list:
                    command_line += ' --searchdomain {0}'.format(searchdomain)
            if 'diskspace' in changed_map:
                self.changed = True
                new_diskspace = changed_map['diskspace'][1]
                command_line += ' --diskspace {0}'.format(new_diskspace)
            if self.kernel['ovz_major_version'] != -1:
                if 'ram' in changed_map:
                    self.changed = True
                    new_ram = changed_map['ram'][1]
                    command_line += ' --physpages {0}'.format(new_ram)
                if 'swap' in changed_map:
                    self.changed = True
                    new_swap = changed_map['swap'][1]
                    command_line += ' --swappages {0}'.format(new_swap)

            rc, stdout, stderr = self.module.run_command(command_line)
            if rc != 0:
                self.module.fail_json(
                    msg="Cannot update the configuration"
                        " of container {0}.\n"
                        "Full line : {1}".format(self.veid, command_line)
                )
        self.module.exit_json(changed=self.changed)


    def create(self):
        """
        Create a new VZ
        """
        create_vz_command = ('vzctl create {veid}').format(
            veid=self.veid,
        )
        # Checking if the openvz kernel is able to do some ploop or not
        # If so, allowing to put the "layout" option and the "diskspace" option
        if self.verify_ploop_availability():
            create_vz_command += " --layout {layout}".format(layout=self.layout)
            if self.diskspace:
                create_vz_command += " --diskspace {diskspace}".format(diskspace=self.diskspace)
        if self.hostname:
            create_vz_command += ' --hostname {0}'.format(self.hostname)
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
                msg="VZ {0} created".format(self.veid),
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
                command = 'vzctl destroy {0}'.format(self.veid)
                rc, stdout, stderr = self.module.run_command(command)
                if rc != 0:
                    self.module.fail_json(
                        msg="Cannot destroy the container {0}".format(self.veid)
                    )
                else:
                    self.changed = True
        self.module.exit_json(changed=self.changed)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            veid=dict(required=True),
            name=dict(),
            layout=dict(choices=['ploop', 'simfs'], required=True),
            hostname=dict(),
            diskspace=dict(),
            ostemplate=dict(),
            config=dict(),
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
        try:
            openvz.create_or_update()
        except OpenVZException, e:
            module.fail_json(msg=e.msg)
    elif module.params['state'] == 'absent':
        openvz.delete()

from ansible.module_utils.basic import *
main()
