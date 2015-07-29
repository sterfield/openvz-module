#!/usr/bin/python
DOCUMENTATION = '''
---
module: openvz
short_description: Create / update / delete / start /stop OpenVZ containers
description:
    - Using this module, you can create, update and delete containers.
version_added: "1.3"
author: Guillaume Loetscher
requirements:
    - an OpenVZ kernel
    - vzctl & vzlist command
options:
    veid:
        description:
            - This is the ID for the OpenVZ container
        required: true
    state:
        description:
            - The state of the container you want to acheive.
        choices: ['present', 'absent', 'started', 'stopped']
        required: true
    name:
        description:
            - Name of the container
        required: false
    hostname:
        description:
            - Hostname of the container
        required: false
    config:
        description:
            - Configuration file used when creating the container
        required: false
    ostemplate:
        description:
            - Template used to create the container
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
            - Allow you to create venet interfaces on your VZ.
            - You can set one or several IPs in this field. You can either
            - set the IP directly as a string, or several IPs using a list.
            - The module will automatically add or remove IPs according to
            - the information you'll provide.
            - Please see the example section.
            - This option is mutually exclusive with option veth
        required: false
    veth:
        description:
            - Allow you to create veth interfaces on your VZ.
            - You can set one or several veths in this field. Each veth can have
            - multiples options, namely "mac", "host_ifname", "host_mac", and "bridge"
            - Please see the example section.
            - This option is mutually exclusive with option ips
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

# Stop a container, ID 123
- openvz:
    veid: 123
    state: stopped

# Start a container, ID 123
- openvz:
    veid: 123
    state: started

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

# Create a container with a veth named eth0. All other veth options are left empty
- openvz
    veid:123
    state: present
    diskspace: unlimited
    ram: 1G
    veth:
      eth0:

# Create a container with two veth. The first one is named eth0 with no other options.
# The second veth is called eth1, with those options :
# - mac: 00:01:02:03:04:05
# - host_ifname : "mainveth"
# - host_mac: 00:01:02:03:04:06
# - bridge : "br0"
- openvz
    veid:123
    state: present
    diskspace: unlimited
    ram: 1G
    veth:
      eth0:
      eth1:
        mac: 00:01:02:03:04:05
        host_ifname: mainveth
        host_mac: 00:01:02:03:04:06
        bridge: br0
'''

VZ_CONF_FOLDER = '/etc/vz/conf/'

# This is the list of variables that are not using "limit" and "barrier"
# but respectively "softlimit" and "hardlimit"
HARDLIMIT_VARS = ('DISKSPACE', 'DISKINODES')
# This is the list of variables that are using "limit" and "barrier"
BARRIER_VARS = ('KMEMSIZE', 'LOCKEDPAGES', 'PRIVVMPAGES', 'SHMPAGES',
                'NUMPROC', 'PHYSPAGES', 'VMGUARPAGES', 'OOMGUARPAGES',
                'NUMTCPSOCK', 'NUMFLOCK', 'NUMPTY', 'NUMSIGINFO', 'TCPSNDBUF',
                'TCPRCVBUF', 'OTHERSOCKBUF', 'DGRAMRCVBUF', 'NUMOTHERSOCK',
                'DCACHESIZE', 'NUMFILE', 'AVNUMPROC', 'NUMIPTENT', 'SWAPPAGES')

MULTIVALUED_VARS = ('IP_ADDRESS', 'NAMESERVER', 'SEARCHDOMAIN')
# This is a list of variables that are using storing their information in pages (4096B on Linux), and not in bytes.
PAGES_VARS = ('LOCKEDPAGES', 'PRIVVMPAGES', 'SHMPAGES', 'PHYSPAGES', 'VMGUARPAGES', 'OOMGUARPAGES', 'SWAPPAGES')


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


class OpenVZExecutionException(OpenVZException):
    pass


class Container(object):

    def __init__(self, module):
        self.module = module
        self.veid = module.params.get('veid')
        self.layout = None
        self.name = None
        self.hostname = None
        self.config = None
        self.ostemplate = None
        self.diskspace = None
        self.ips = None
        self.veth = None
        self.nameserver = None
        self.onboot = None
        self.ram = None
        self.swap = None
        self.searchdomain = None
        self.check_veid()

    def check_veid(self):
        if type(self.veid) is not int:
            try:
                veid = int(self.veid)
            except ValueError:
                raise OpenVZConfigurationException("You haven't provided a valid integer as an OpenVZ ID")
            else:
                self.veid = veid

    @staticmethod
    def set_onboot(value):
        """In OpenVZ, onboot can have only two value :
        * "yes"
        * "no"
        However, in Ansible, if you put the string "yes" or "on" in a variable, Ansible will convert this value as True.
        Same for "no" or "off", which convert to False.
        As a result, checking if True or False, and convert it to "yes" or "no", accordingly.
        """
        if value is None:
            return None
        elif value or value == 'yes' or value == 'on':
            return "yes"
        else:
            return "no"

    @staticmethod
    def convert_to_list(value):
        """Get the value that could be a list or a string.
        If it's a string, put it into a list, and return it. This function
        comes in handy, as the user is able to provide either lists, or a
        single string as data. For example, he can provide a list of IPS,
        or a single IP.
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
            raise OpenVZConfigurationException(
                "You haven't provide an integer as ram / swap size"
            )
        if value % 4096 == 0:
            return value / 4096
        else:
            return (value / 4096) + 1

    @staticmethod
    def convert_space_unit(value_w_suffix, pages=False):
        """Take the space given in argument :
        - If there's a suffix (G, T, etc..), convert the space in bytes.
        - If the value is already an int, then there's no conversion to do. Therefore returning the value.
        - If the value is "unlimited", return 9223372036854775807 (value equal to "unlimited" in OpenVZ).
        - If the argument "pages" = True, then it means that the value is in "number of pages", and not "number of
        bytes". So if the value for "swappages" in the configuration file is "0:256M", it means that the user wants
        to have 256 MB of RAM, but this value will be showed as "barrier:0, limit: 65536" in "vzlist -j"
        (because 65536 pages * 4096 = 256MB).
        This is a real mess, so trying to convert every PAGES_VARS in pages, in order to have a consistent view,
        whatever the source (config file or vzlist).
        """
        if value_w_suffix == 'unlimited':
            return 9223372036854775807
        try:
            result = float(value_w_suffix)
        except (TypeError, ValueError):
            try:
                # Most likely, the user entered a string like "18G". Taking the
                # last character, and catching the rest as a value.
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
            if pages:
                result /= 4096
        return int(result)

    def veth_difference(self, other):
        """Take the veth expected and the current veth configuration on the container, and create all the command line
        options in order to add / remove / update the veth accordingly.
        """
        result = []

        veth_to_add = set(self.veth) - set(other.veth)
        for ifname in veth_to_add:
            result.append('--netif_add {0},{1},{2},{3},{4}'.format(
                ifname,
                self.veth[ifname]['mac'],
                self.veth[ifname]['host_ifname'],
                self.veth[ifname]['host_mac'],
                self.veth[ifname]['bridge'],
            ))

        veth_to_remove = set(other.veth) - set(self.veth)
        result += ['--netif_del {0}'.format(ifname) for ifname in veth_to_remove]

        veth_already_present = set(other.veth) & set(self.veth)
        # There's already a veth with the same ifname. Verifying if the parameters needs to be updated
        for ifname in veth_already_present:
            update_veth_list = []
            for param, value in self.veth[ifname].iteritems():
                # iterate over the list of parameters entered by the user. As all parameters are optional in Ansible
                # there's a modification only if the user parameter is not empty and the current parameter is
                # different.
                if value and value != other.veth[ifname][param]:
                    update_veth_list.append('--{0} {1}'.format(param, self.veth[ifname][param]))
            if update_veth_list:
                # If there's something in update_veth_list, then it means that the user mentionned an already
                # existing veth interface, but with a different parameter. So adding the name of the interface in
                # the option '--ifname'
                update_veth_list.insert(0, '--ifname {0}'.format(ifname))
            result += update_veth_list

        return result

    def __sub__(self, other):
        """Return the difference between the current object and the "other" one.
        Only MEANINGFUL differences will be returned.
        For example, if there's a difference regarding the ram, it's a value that can be updated
        on the container, so it'll be returned.
        If there's a difference of configuration file, or layout, it's a value that cannot be changed
        on the container (except destroying it and recreating it), so it'll NEVER be returned as a difference.
        Return an array containing all the options to update the said containers, in order to be similar as the
        "other" container.
        """
        array = []
        if self.name and self.name != other.name:
            array.append('--name {0}'.format(self.name))
        if self.hostname and self.hostname != other.hostname:
            array.append('--hostname {0}'.format(self.hostname))
        if self.diskspace and self.diskspace != other.diskspace:
            array.append('--diskspace {0}'.format(self.diskspace))
        if set(self.ips) != set(other.ips):
            ips_to_remove = set(self.ips) - set(other.ips)
            ips_to_add = set(other.ips) - set(self.ips)
            array += ['--ipadd {0}'.format(ip) for ip in ips_to_add]
            array += ['--ipdel {0}'.format(ip) for ip in ips_to_remove]

        array += self.veth_difference(other)

        if self.nameserver and set(self.nameserver) != set(other.nameserver):
            array += ['--nameserver {0}'.format(ns) for ns in self.nameserver]
        if self.searchdomain and set(self.searchdomain) != set(other.searchdomain):
            array += ['--searchdomain {0}'.format(sd) for sd in self.searchdomain]
        if self.onboot and self.onboot != other.onboot:
            array.append('--onboot {0}'.format(self.onboot))
        if self.ram and self.ram != other.ram:
            array.append('--physpages {0}'.format(self.ram))
        if self.swap and self.swap != other.swap:
            array.append('--swappages {0}'.format(self.swap))
        return array


class ExpectedContainer(Container):

    def __init__(self, module):
        super(ExpectedContainer, self).__init__(module)
        self.layout = self.module.params.get('layout')
        self.name = self.module.params.get('name')
        self.hostname = self.module.params.get('hostname')
        self.config = self.module.params.get('config')
        self.ostemplate = self.module.params.get('ostemplate')
        self.diskspace = self.module.params.get('diskspace')
        self.ips = self.module.params.get('ips') if self.module.params.get('ips') is not None else []
        self.veth = self.module.params.get('veth') if self.module.params.get('veth') is not None else {}
        self.nameserver = self.module.params.get('nameserver')
        self.onboot = Container.set_onboot(self.module.params.get('onboot'))
        self.ram = self.module.params.get('ram')
        self.swap = self.module.params.get('swap')
        self.searchdomain = self.module.params.get('searchdomain')
        if self.diskspace:
            # Converting the space value in bytes. However, this value will then be used in '--diskspace', which is
            # in kbytes. Hence the division by 1000
            self.diskspace = ExpectedContainer.convert_space_unit(self.diskspace)
            self.diskspace /= 1000
        if self.ram:
            self.ram = ExpectedContainer.convert_space_unit(self.ram)
            self.ram = ExpectedContainer.convert_pages(self.ram)
        if self.swap:
            self.swap = ExpectedContainer.convert_space_unit(self.swap)
            self.swap = ExpectedContainer.convert_pages(self.swap)
        if self.ips:
            self.ips = ExpectedContainer.convert_to_list(self.ips)
        if self.nameserver:
            self.nameserver = ExpectedContainer.convert_to_list(self.nameserver)
        if self.searchdomain:
            self.searchdomain = ExpectedContainer.convert_to_list(self.searchdomain)
        self.verify_veth_parameters()

    def verify_veth_parameters(self):
        """Take the "veth" dictionary from the user, and verify it.
        - is there a non-empty value for the "ifname" key ?
        - is it a dict ?
        Return also default empty values for optional veth parameters
        """
        if self.veth:
            if not isinstance(self.veth, dict):
                raise OpenVZConfigurationException("The 'veth' paramater doesn't seems to be properly entered.\n"
                                                   "Please enter a dictionary, with at least a 'ifname' key.\n"
                                                   "Please see the examples.")
            for veth, veth_param in self.veth.iteritems():
                # take all veth paramaters stored in a dict, and update them with the value or an empty string,
                # if they are not present.
                if veth_param is None:
                    veth_param = {}
                temp_dict = {
                    'mac': veth_param.get('mac', ''),
                    'host_ifname': veth_param.get('host_ifname', ''),
                    'host_mac': veth_param.get('host_mac', ''),
                    'bridge': veth_param.get('bridge', ''),
                }
                self.veth[veth] = temp_dict

    @staticmethod
    def veth_option_verification(veth):
        """Take the veth value entered by the user and verify it.
        """
        if veth and veth is not dict:
            raise OpenVZConfigurationException('Option veth seems to be '
                                               'incorrectly setup !')
        for veth, options in veth.iteritems():
            if set(options) != {'mac', 'host_ifname', 'host_mac', 'bridge'}:
                raise OpenVZConfigurationException('The veth option does not '
                                                   'have the correct set of'
                                                   ' options !')

    def create(self):
        """
        Return an array with all the arguments to create an OpenVZ container.
        That way, the hypervisor can get the command, remove some parts if needed (for example,
        you cannot do ploop if the kernel is too old, or you cannot put a "--layout" option).
        """
        create_vz_command = []
        create_vz_command.append("--layout {layout}".format(layout=self.layout))
        if self.diskspace:
            create_vz_command.append("--diskspace {diskspace}".format(diskspace=self.diskspace))
        if self.hostname:
            create_vz_command.append('--hostname {0}'.format(self.hostname))
        if self.ostemplate:
            create_vz_command.append(' --ostemplate {0}'.format(self.ostemplate))
        if self.config:
            create_vz_command.append(' --config {0}'.format(self.config))
        if self.ips:
            for ip in self.ips:
                create_vz_command.append(' --ipadd {0}'.format(ip))
        return create_vz_command


class CurrentContainer(Container):

    def __init__(self, module):
        super(CurrentContainer, self).__init__(module)
        self.status = None

        self.config_map = self.get_configuration()
        self.convert_configuration_to_object(self.config_map)

    def convert_configuration_to_object(self, config_map):
        """Get all the information gathered using either:
        * vzlist -j (if available)
        * or the configuration file.
        From that, populate the current object with all the needed variables.
        The goal is to have a "CurrentContainer" object which has every properties filled
        with the correct information. That way, it's more easier to compare objects between
        them
        """
        self.layout = config_map.get('layout', 'simfs')
        self.name = config_map.get('name', '')
        self.hostname = config_map.get('hostname', '')
        self.config = config_map.get('config', '/etc/vz/conf/{0}.conf'.format(self.veid))
        self.ostemplate = config_map.get('ostemplate', '')
        self.ips = config_map.get('ips', [])
        self.veth = config_map.get('veth', [])
        self.nameserver = config_map.get('nameserver', [])
        self.searchdomain = config_map.get('searchdomain', [])
        self.onboot = Container.set_onboot(config_map.get('onboot', 'no'))
        self.status = config_map.get('status')
        try:
            if config_map['diskspace']['hardlimit'] == 9223372036854775807:
                self.diskspace = 9223372036854775807
            else:
                self.diskspace = config_map['diskspace']['hardlimit']
        except KeyError:
            self.diskspace = 9223372036854775807
        try:
            if config_map['physpages']['limit'] == 9223372036854775807:
                self.ram = 9223372036854775807
            self.ram = config_map['physpages']['limit']
        except KeyError:
            self.ram = 9223372036854775807
        try:
            if config_map['swappages']['limit'] == 9223372036854775807:
                self.swap = 9223372036854775807
            self.swap = config_map['swappages']['limit']
        except KeyError:
            self.swap = 9223372036854775807

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
            - a small dictionary, containing "softlimit" and "hardlimit" as
              keys if the variable is listed in HARDLIMIT_VARS
            - a small dictionary, containing "barrier" and "limit" as keys, if
              the variable is not listed in HARDLIMIT_VARS
            - a list of values if the variable is listed as MULTIVALUED_VARS
        """
        config_map = {}
        for variable, value in result_list:
            if variable in HARDLIMIT_VARS:
                if ':' in value:
                    softlimit, hardlimit = value.split(':')
                    softlimit = CurrentContainer.convert_space_unit(softlimit)
                    hardlimit = CurrentContainer.convert_space_unit(hardlimit)
                else:
                    # The variable should be using the format
                    # "softlimit:hardlimit" but for unknown reason, sometimes,
                    # there's only one value for the variable. So storing the
                    # same value for barrier and limit.
                    softlimit = hardlimit = CurrentContainer.convert_space_unit(value)
                config_map[variable.lower()] = {
                    'softlimit': softlimit,
                    'hardlimit': hardlimit,
                }
            elif variable in BARRIER_VARS:
                if variable in PAGES_VARS:
                    pages = True
                else:
                    pages = False
                if ':' in value:
                    barrier, hardlimit = value.split(':')
                    barrier = CurrentContainer.convert_space_unit(barrier, pages=pages)
                    limit = CurrentContainer.convert_space_unit(hardlimit, pages=pages)
                else:
                    # The variable should be using the format
                    # "barrier:limit" but for unknown reason, sometimes,
                    # there's only one value for the variable. So storing the
                    # same value for barrier and limit.
                    barrier = limit = CurrentContainer.convert_space_unit(value, pages=pages)
                config_map[variable.lower()] = {
                    'barrier': barrier,
                    'limit': limit,
                }
            else:
                if variable in MULTIVALUED_VARS:
                    # Those variables are storing multiple values, separated by
                    # a space, As a result, splitting the value to get an array.
                    if variable == 'IP_ADDRESS':
                        # in old OpenVZ kernel, IPs are stored in variable
                        # "IP_ADDRESS" where in new kernel, they are stored in
                        # the JSON structure in the "ip" key. Using "ip" key
                        #  as a common key.
                        config_map['ips'] = value.split()
                    else:
                        config_map[variable.lower()] = value.split()
                elif variable == 'NETIF':
                    # veth are separated by ';' so retrieving the array of veth
                    # by splitting it.
                    veth_list = value.split(';')
                    veth_extract_dict = {}
                    for veth in veth_list:
                        veth_extract_dict.update(
                            CurrentContainer.extract_veth_information(veth)
                        )
                    config_map['veth'] = veth_extract_dict
                else:
                    # Trying to convert the value in integer. If it fails, then
                    # it's most likely a string, then copy it as it is
                    try:
                        config_map[variable.lower()] = int(value)
                    except (TypeError, ValueError):
                        config_map[variable.lower()] = value
        return config_map

    def get_container_file_configuration(self):
        """Get a container configuration from the configuration file, normally
        stored in /etc/vz/conf/<veid>.conf.
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
        return CurrentContainer.extract_variable_information(result)

    def get_vzlist_json_configuration(self):
        """Getting the configuration of a said container using "vzlist -j".
        On some older kernels (OpenVZ from Debian 6 for example), the vzlist
        doesn't have a JSON output, so it'll failed. Returning an empty dict
        in that case.
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

    def get_configuration(self):
        """Get the configuration of only one container.
        """
        json_config_map = self.get_vzlist_json_configuration()
        file_config_map = self.get_container_file_configuration()

        if json_config_map and file_config_map:
            json_config_map['diskspace'] = file_config_map['diskspace']
            # Veth information are only stored in the config file
            json_config_map['veth'] = file_config_map.get('veth', {})
            return json_config_map
        elif file_config_map:
            # Get the status of the container through vzlist
            file_config_map['status'] = CurrentContainer.get_container_status(self.veid)
            return file_config_map
        else:
            raise OpenVZConfigurationException(
                "Cannot retrieve information from either vzlist JSON output "
                "or from the configuration file."
            )

    @staticmethod
    def get_container_status(veid):
        """
        Take the VEID in argument, and retrieve the status of the container.
        This function is only useful when working with a version of vzlist
        that is not providing the JSON output, because the status is not
        registered in the configuration file.
        """
        vzlist_command = "vzlist -a1 -o status {0}".format(veid)
        args = shlex.split(vzlist_command)
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        rc = process.wait()
        stdout = process.stdout.read().rstrip('\n')
        stderr = process.stderr.read().rstrip('\n')
        if rc != 0:
            raise OpenVZListException(
                "Cannot retrieve the status for the container {0}\n"
                "stderr: {1}".format(veid, stderr)
            )
        else:
            return stdout

    def delete(self):
        """Try to delete a container.
        Return True if the hypervisor managed to destroy the container
        Raise exceptions if :
        * the container is not stopped
        * the container cannot be destroyed, for an unknown reason
        """
        if self.status != 'stopped':
                raise OpenVZExecutionException("Cannot destroy the container, it's not stopped !")
        else:
            command = 'vzctl destroy {0}'.format(self.veid)
            rc, stdout, stderr = self.module.run_command(command)
            if rc != 0:
                raise OpenVZExecutionException("Cannot destroy the container {0}".format(self.veid))
            else:
                return True

    def start(self):
        """Try to start a container
        Return False if the container is already started (as there's no modification)
        Return True if the container is started by the hypervisor
        Raise an Exception if there's some other issues.
        """
        if self.status == 'running':
            return False
        else:
            start_command = 'vzctl start {0}'.format(self.veid)
            rc, stdout, stderr = self.module.run_command(start_command)
            if rc != 0 and rc != 32:
                # return code = 32 is sent when a container is already started
                # and you asked to start it again.
                raise OpenVZExecutionException(
                    "Cannot start the VZ !\n"
                    "stderr: {0}".format(stderr)
                )
            else:
                return True

    def stop(self):
        """Try to stop a container
        Return False if the container is already stopped (as there's no modification)
        Return True if the container is stopped by the hypervisor
        Raise an Exception if there's some other issues.
        """
        if self.status == 'stopped':
            return False
        else:
            stop_command = 'vzctl stop {0}'.format(self.veid)
            rc, stdout, stderr = self.module.run_command(stop_command)
            if rc != 0:
                raise OpenVZExecutionException(
                    "Cannot stop the VZ {0}!\n"
                    "stderr: {1}".format(self.veid, stderr)
                )
            else:
                return True

    @staticmethod
    def extract_veth_information(veth_string):
        """
        Get the VETH string from the configuration file, extract the values
        * ifname
        * bridge
        * mac
        * host_ifname
        * host_mac
        Return a dictionary with the 'ifname' as key and the other parameters as dictionary values
        """
        result_dict = {}
        if not veth_string:
            return result_dict
        for veth_option in veth_string.split(','):
            option, value = veth_option.split('=')
            result_dict[option] = value
        if "bridge" not in result_dict:
            # No bridge was defined on this veth, but to have a consistent
            # output, add the option in the output dict.
            result_dict['bridge'] = ''

        return {result_dict.pop('ifname'): result_dict}


class Hypervisor(object):

    def __init__(self, module):
        self.module = module
        self.veid_list = self.get_veid_list()
        self.kernel = self.get_kernel_version()
        self.expected_container = ExpectedContainer(self.module)

        if self.module.params['layout'] == 'ploop' and not self.is_ploop_available():
            raise OpenVZKernelException("The current kernel is too old to create OpenVZ containers with ploop !")

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
                    "vzlist is not installed or failed to be executed"
                    "properly.\n Stderr : {0}".format(stderr)
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

    def get_kernel_version(self):
        """Get the kernel version by calling "uname -r". It will allow to check
        if this is indeed an OpenVZ kernel, and what can be done (for example,
         you cannot do ploop on old OpenVZ kernels"""
        kernel = {
            'linux_kernel': '',
            'architecture': '',
            'ovz_major_version': -1,
            'ovz_minor_version': -1,
            'ovz_branch': '',
            'ovz_addon_number': -1,
        }
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
                kernel['linux_kernel'] = linux_kernel

                # if the string is equal to "amd64", then it's an old
                #  OpenVZ kernel, issued from Debian 6 repository.
                if ovz_string == "amd64":
                    kernel['architecture'] = 'amd64'
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
                        kernel['ovz_major_version'] = int(
                            result.group('ovz_major_version')
                        )
                        kernel['ovz_branch'] = result.group('ovz_branch')
                        kernel['ovz_minor_version'] = int(
                            result.group('ovz_minor_version')
                        )
                        kernel['ovz_addon_number'] = int(
                            result.group('ovz_addon_number')
                        )
                        kernel['architecture'] = result.group(
                            'architecture'
                        )
                    else:
                        raise OpenVZKernelException(
                            "Cannot extract OpenVZ information from the"
                            " kernel. Is is OpenVZ ?"
                            " Current kernel : {0}".format(stdout)
                        )
        return kernel

    def is_ploop_available(self):
        """Comparing OpenVZ minor_version and major_version, and according to
        the values, return True or False if the kernel can manage ploop
        """
        return (self.kernel['ovz_major_version'] >= 42 and
                self.kernel['ovz_minor_version'] >= 58)

    def is_vswap_available(self):
        """Openvz have made a big change in the resources limitation / quotas. The new accounting system is called
        VSwap (https://wiki.openvz.org/VSwap) and is available in kernel 042stab04x kernels.
        In short, it means that every non-VSwap is not capable to handle swap / ram quotas correctly (well, at least
        according to the man vzctl :
            "For older kernels, this is an accounting-only parameter, showing the usage
             of RAM by this container. Barrier should be set to 0, and limit should be set to unlimited."
        This function will return True if the current kernel is Vswap compatible or not.
        """
        return (self.kernel['ovz_major_version'] >= 42 and
                self.kernel['ovz_minor_version'] >= 40)

    def verify_create_command_line(self, command_line):
        """Take an array in entry, which is the complete command line, with all the switches and options.
        Remove some parts, mainly because the kernel is too old
        """
        if not self.is_ploop_available():
            for option in command_line[:]:
                if '--layout' in option:
                    command_line.remove(option)
                if '--diskspace' in option:
                    command_line.remove(option)

    def verify_update_command_line(self, command_line):
        """Take an array in entry, which is the complete command line, with all the switches and options.
        Remove some parts, mainly because the kernel is too old
        """
        if not self.is_vswap_available():
            for option in command_line[:]:
                if '--physpages' in option:
                    command_line.remove(option)
                if '--swappages' in option:
                    command_line.remove(option)

    def create_or_update_container(self):
        """Check if the container already exists. If yes, update it (if
        needed. If no, create it.
        Return :
         - True if the container is indeed created / updated
         - False if not
        """
        changed = False
        if self.expected_container.veid not in self.veid_list:
            create_vz_command = self.expected_container.create()
            self.verify_create_command_line(create_vz_command)
            create_vz_command.insert(0, 'vzctl create {0}'.format(self.expected_container.veid))
            rc, stdout, stderr = self.module.run_command(' '.join(create_vz_command))
            if rc != 0:
                raise OpenVZExecutionException('The "vzctl create" command failed !\n'
                                               'Command invoked : {0}\n'
                                               'Stderr : {1}\n'.format(' '.join(create_vz_command), stderr))
            changed = True
        current_container = CurrentContainer(self.module)
        # Getting all the configuration from the currently running container
        # then doing a diff between the running configuration and the expected configuration
        # It'll return an array, containing all the command line + options to update the container
        # accordingly
        update_vz_command = self.expected_container - current_container
        self.verify_update_command_line(update_vz_command)
        if update_vz_command:
            update_vz_command.insert(0, 'vzctl set {0}'.format(self.expected_container.veid))
            update_vz_command.append('--save')
            rc, stdout, stderr = self.module.run_command(' '.join(update_vz_command))
            if rc != 0:
                raise OpenVZExecutionException('The "vzctl set" command failed !\n'
                                               'Command invoked : {0}\n'
                                               'Stderr : {1}\n'.format(' '.join(update_vz_command), stderr))
            changed = True
        return changed

    def is_vz_not_present(self):
        if self.expected_container.veid not in self.veid_list:
            return True
        else:
            return False

    def delete_container(self):
        """Check if the said veid is indeed on the hypervisor. If so, and if the container is stopped, destroy it.
        If it's not stopped, raise an Exception with the appropriate message.
        If the veid is not present on the hypervisor, return that nothing was done.
        """
        if self.is_vz_not_present():
            return False
        else:
            current_container = CurrentContainer(self.module)
            return current_container.delete()

    def start_container(self):
        """
        Start an OpenVZ container
        """
        if self.is_vz_not_present():
            return False
        else:
            current_container = CurrentContainer(self.module)
            return current_container.start()

    def stop_container(self):
        """
        Stop an OpenVZ container
        """
        if self.is_vz_not_present():
            return False
        else:
            current_container = CurrentContainer(self.module)
            return current_container.stop()


def main():
    module = AnsibleModule(
        argument_spec=dict(
            veid=dict(required=True),
            name=dict(),
            layout=dict(
                choices=['ploop', 'simfs'],
                default='simfs'
            ),
            hostname=dict(),
            diskspace=dict(),
            ostemplate=dict(),
            config=dict(),
            ips=dict(),
            veth=dict(),
            onboot=dict(),
            nameserver=dict(),
            searchdomain=dict(),
            ram=dict(),
            swap=dict(),
            state=dict(
                choices=['present', 'absent', 'stopped', 'started'],
                required=True
            )
        ),
        mutually_exclusive=[
            ['ips', 'veth']
        ]
    )

    try:
        result = False
        hypervisor = Hypervisor(module)
        if module.params['state'] == 'present':
            result = hypervisor.create_or_update_container()
        elif module.params['state'] == 'absent':
            result = hypervisor.delete_container()
        elif module.params['state'] == 'started':
            result = hypervisor.start_container()
        elif module.params['state'] == 'stopped':
            result = hypervisor.stop_container()
    except OpenVZException, e:
        module.fail_json(msg=e.msg)
    else:
        module.exit_json(changed=result)


from ansible.module_utils.basic import *
main()
