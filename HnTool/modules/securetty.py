#coding: utf-8

import stat
import os
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule


class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name = 'securetty'
        self.long_name = 'Checa por vulnerabilidades no arquivo securetty'
        self.type = 'config'
        self.required_files = ['/etc/securetty']

    def requires(self):
        return self.required_files

    def analyze(self, options):
        check_results = self.check_results
        securetty_conf_file = self.required_files

        for securetty_conf in securetty_conf_file:
            if os.path.isfile(securetty_conf):
                # dicionario com todas as linhas
                lines = HnTool.modules.util.hntool_conf_parser(securetty_conf)
                # verifica quantos root podem logar via login, gdm, xdm

                # recomendado 600
                permissao = oct(os.stat(securetty_conf)[stat.ST_MODE] & 0777)

                if permissao > oct(0600):
                    msg = 'Permissão no arquivo securetty é maior que 600'
                    check_results['high'].append(msg)
                else:
                    msg = 'Permissão no arquivo securetty ' + \
                        'está correta ({0})'.format(permissao)
                    check_results['ok'].append(msg)

        return check_results
