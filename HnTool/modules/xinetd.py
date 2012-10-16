#coding: utf-8

import os
import stat
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule


class Rule(MasterRule):
    '''
    Classe para verificar vulnerabilidades nos arquivos do xinetd
    '''
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name = 'xinetd'
        self.long_name = 'Checa a permissão dos arquivos do xinetd'
        self.type = 'config'
        self.required_files = ['/etc/xinetd.d', '/etc/xinetd.conf']

    def requires(self):
        '''This method should return all the required files to run
        the module. Usually, it's the same as self.required_files'''
        return self.required_files

    def analyze(self, options):
        '''Checa a permissão dos arquivos do xinetd'''
        check_results = self.check_results
        xinetdd_file = self.required_files[0]
        xinetd_conf_file = self.required_files[1]

        if oct(os.stat(xinetdd_file)[stat.ST_MODE] & 0777) > 0700:
            msg = '{0} tem permissão maior que 700'.format(xinetdd_file)
            check_results['low'].append(msg)
        else:
            msg = '{0} tem permissão 700'.format(xinetdd_file)
            check_results['ok'].append(msg)
        if oct(os.stat(xinetd_conf_file)[stat.ST_MODE] & 0777) > 0600:
            msg = '{0} tem permissão maior que 600'.format(xinetd_conf_file)
            check_results['low'].append(msg)
        else:
            msg = '{0} tem permissão 600'.format(xinetd_conf_file)
            check_results['ok'].append(msg)

        return check_results
