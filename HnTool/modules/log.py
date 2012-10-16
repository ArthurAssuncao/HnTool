#coding: utf-8

import os
import stat
import glob
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule


class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name = 'log'
        self.long_name = 'Checa a permissão nos arquivos de log do sistema'
        self.type = 'services'
        self.required_files = None

    def requires(self):
        return self.required_files

    def analyze(self, options):
        check_results = self.check_results
        log_dir = '/var/log/*'
        files_dirs = glob.iglob(log_dir)

        for file_dir in files_dirs:
            permission = oct(os.stat(file_dir)[stat.ST_MODE] & 0777)
            if int(permission) % 10 != 0:  # outros nao devem ter acesso
                msg = '{0} tem permissão maior que 0 para outros'.format(file_dir)
                check_results['low'].append(msg)

        if check_results['low'] == []:
            msg = 'Arquivos de log tem permissão xx0'
            check_results['ok'].append(msg)

        return check_results
