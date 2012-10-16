#coding: utf-8

import stat
import os
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule


class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name = 'grub'
        self.long_name = 'Checa por vulnerabilidades no ' + \
            'arquivo de configuracao do grub'
        self.type = 'config'
        self.required_files = ['/boot/grub/grub.cfg', '/etc/default/grub', '/etc/grub.d/00_header']

    def requires(self):
        return self.required_files

    def analyze(self, options):
        check_results = self.check_results
        grub_conf_file = self.required_files

        # senha no grub
        grub_header = self.required_files[2]
        if os.path.isfile(grub_header):
            try:
                arq = open(grub_header, 'r')
                lines = arq.readlines()
                for line in lines:
                    if line[0] != '#' and 'password ' in line:
                        msg = 'Grub está protegido com senha, mas não usa encryptação'
                        check_results['low'].append(msg)
                        break
                    elif line[0] != '#' and 'password_pbkdf2 ' in line:
                        encriptacao = line.split(' ')[2].split('.')[2]
                        msg = 'Grub está protegido com senha, usando {0}'.format(encriptacao)
                        check_results['ok'].append(msg)
                        break
                else:
                    check_results['high'].append('Grub não está usando senha')
            except IOError, (errno, strerror):
                msg = 'Não foi possivel abrir {0}: {1}'.format(limits_file_path, strerror)
                check_results[4].append(msg)
            finally:
                arq.close()

        for i in xrange(len(grub_conf_file) - 1):
            grub_conf = grub_conf_file[i]
            if os.path.isfile(grub_conf):
                # recomendado 400 ou 600
                permissaoGrub = oct(os.stat(grub_conf)[stat.ST_MODE] & 0777)
                if permissaoGrub == oct(0600) or permissaoGrub == oct(0400):
                    msg = 'Permissão no arquivo {0} está correta ({1})'.format(grub_conf, permissaoGrub)
                    check_results['ok'].append(msg)
                elif permissaoGrub > oct(0400):
                    msg = 'Permissão no arquivo {0} é maior que 400 e diferente de 600'.format(grub_conf)
                    check_results['high'].append(msg)

        return check_results
