#!/usr/bin/python
import json

OPENVZ_COMMANDS = [
    'create'
]


class OpenVZ():

    def __init__(self, module):
        self.module = module
        self.veid = module.params.get('veid')
        self.name = module.params.get('name')
        self.hostname = module.params.get('hostname')
        self.ostemplate = module.params.get('ostemplate')
        self.diskspace = module.params.get('diskspace')
        self.ip = module.params.get('ip')

    def check_veid(self):
        if not self.veid:
            self.module.fail_json(msg="You haven't provided any OpenVZ ID")
        if type(self.veid) is not int:
            try:
                veid = int(self.veid)
            except ValueError:
                self.module.fail_json(msg="You haven't provided a valid "
                                          "integer as an OpenVZ ID")
            return veid
        else:
            return self.veid

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

    def create(self):
        """ Check if all arguments needed are filled, and if the VZ is not already
        created on the hypervisor with the same ID. If all checks are green,
        create the VZ"""

        veid = self.check_veid()
        veid_list = self.get_veid_list()
        if veid in veid_list:
            self.module.fail_json(msg="The VZ ID you want to create is already"
                                      " in use on the hypervisor. Please"
                                      " choose another one.")

        if not self.diskspace:
            self.module.fail_json(msg="You haven't provided any diskspace")

        create_vz_command = (
            'vzctl create {veid} --layout ploop'
            ' --diskspace {diskspace}'
            ).format(
                veid=self.veid,
                diskspace=self.diskspace
            )
        if self.hostname:
            create_vz_command += ' --hostname {0}'.format(self.hostname)
        if self.name:
            create_vz_command += ' --name {0}'.format(self.name)
        if self.ostemplate:
            create_vz_command += ' --ostemplate {0}'.format(self.ostemplate)
        if self.ip:
            ip_command = ''
            if type(self.ip) is list:
                for ip in self.ip:
                    ip_command += ' --ipadd {0}'.format(ip)
            else:
                ip_command += ' --ipadd {0}'.format(self.ip)
        rc, stdout, stderr = self.module.run_command(create_vz_command)
        if rc != 0:
            self.module.fail_json(msg="Failed to create the VZ !\n"
                                      "stderr : {0}".format(stderr))
        else:
            self.module.exit_json(msg="VZ {} created".format(self.veid))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            command=dict(choices=OPENVZ_COMMANDS, required=True),
            veid=dict(),
            name=dict(),
            hostname=dict(),
            diskspace=dict(),
            ostemplate=dict(),
            ip=dict(),
        )
    )

    openvz = OpenVZ(module)
    if module.params['command'] == 'create':
        openvz.create()

from ansible.module_utils.basic import *
main()
