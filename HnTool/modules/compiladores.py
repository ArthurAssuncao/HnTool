#coding: utf-8

import os
import stat
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule


class Rule(MasterRule):
    '''
    Classe para verificar vulnerabilidades nos arquivos dos compiladores
    '''
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name = 'compiladores'
        self.long_name = 'Checa a permissão dos compiladores'
        self.type = 'files'
        self.required_files = ['/usr/bin/gcc', '/usr/bin/cc']

    def requires(self):
        '''This method should return all the required files to run
        the module. Usually, it's the same as self.required_files'''
        return self.required_files

    def analyze(self, options):
        '''Checa a permissão dos compiladores'''
        check_results = self.check_results

        permission = oct(0700)
        for compiler_file in self.required_files:
            if oct(os.stat(compiler_file)[stat.ST_MODE] & 0777) > permission:
                msg = '{0} tem permissão maior que {1}'.format(compiler_file, int(permission))
                check_results['high'].append(msg)
            else:
                msg = '{0} tem permissão {1}'.format(compiler_file, int(permission))
                check_results['ok'].append(msg)

        return check_results
