#coding: utf-8

import os
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule
import re


class Rule(MasterRule):
    '''
    Classe para verificar vulnerabilidades no arquivo limits.conf
    '''
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name = 'Limits'
        self.long_name = 'Checa pela vulnerabilidade fork bomb'
        self.type = 'config'
        self.required_files = ['/etc/pam.d/su', '/etc/security/limits.conf']
        # ps aux | wc -l == numero de processos atual do usuario

    def requires(self):
        '''This method should return all the required files to run
        the module. Usually, it's the same as self.required_files'''
        return self.required_files

    def analyze(self, options):
        '''Checa pela vulnerabilidade fork bomb'''
        check_results = self.check_results
        pam_file_path = self.required_files[0]
        limits_file_path = self.required_files[1]

        # verifica se o pam esta habilitado
        if os.path.isfile(pam_file_path):
            try:
                arq = open(pam_file_path, 'r')
                linhas = [l.strip('\n') for l in arq.readlines()]

                for linha in linhas:
                    if 'pam_limits.so' in linha and linha.strip()[0] == 's':  # s de session
                        # pam habilitado
                        if os.path.isfile(limits_file_path):
                            try:
                                arq = open(limits_file_path, 'r')
                                linhas = [l.strip('\n') for l in arq.readlines()]

                                root_limit = False
                                regex = re.compile(r'(.+?) +(.+?) +(.+?) +(.+)')
                                for linha in linhas:
                                    linha = linha.strip()
                                    if 'nproc' in linha and linha[0] != '#':  # and 'soft' in linha:
                                        try:
                                            dados = re.findall(regex, linha)[0]
                                            if dados[0][0] == '@':  # grupo
                                                msg = 'Usuários do grupo {0} tem limite de {1} processos'.format(dados[0][1::], dados[3])
                                                if dados[0] == '@root':
                                                    root_limit = True
                                            elif dados[0][0] == '*':  # todos
                                                msg = 'Todos usuários tem limite de {0} processos'.format(dados[3])
                                                root_limit = True
                                            else:  # usuario
                                                msg = 'Usuário {0} tem limite de {1} processos'.format(dados[0], dados[3])
                                                if dados[0] == 'root':
                                                    root_limit = True
                                            check_results['ok'].append(msg)
                                        except IndexError, error:
                                            msg = 'Formato de linha errado: {0} - {1}'.format(error)
                                            check_results[4].append(msg)
                                if not root_limit:
                                    msg = 'Root não tem limite de processos'
                                    check_results['high'].append(msg)
                            except IOError, (errno, strerror):
                                msg = 'Não foi possivel abrir {0}: {1}'.format(limits_file_path, strerror)
                                check_results[4].append(msg)
                            finally:
                                arq.close()
                                break
                else:
                    msg = 'PAM não habilitado, usuários não tem limite de processos'
                    check_results['high'].append(msg)

            except IOError, (errno, strerror):
                msg = 'Não foi possivel abrir {0}: {1}'.format(sysctl, strerror)
                check_results[4].append(msg)

        return check_results
