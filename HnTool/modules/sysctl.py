#coding: utf-8

import re
import stat
import os
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule


class Rule(MasterRule):
    '''
    Classe para verificar vulnerabilidades no arquivo sysctl.conf
    '''
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name = 'sysctl'
        self.long_name = 'Checa por vulnerabilidades de internet no arquivo sysctl'
        self.type = 'config'
        self.required_files = ['/etc/sysctl.conf']

    def requires(self):
        '''This method should return all the required files to run
        the module. Usually, it's the same as self.required_files'''
        return self.required_files

    def analyze(self, options):
        '''Checa por vulnerabilidades de internet no arquivo sysctl'''
        check_results = self.check_results
        sysctl_conf_file = self.required_files

        for sysctl in sysctl_conf_file:
            if os.path.isfile(sysctl):
                try:
                    arq = open(sysctl, 'r')
                except IOError, (errno, strerror):
                    msg = 'Não foi possivel abrir {0}: {1}'.format(sysctl, strerror)
                    check_results[4].append(msg)
                    continue
                l = [l.strip('\n').replace(' ', '') for l in arq.readlines()]
                linhas = l

                #Protecao contra IP Spoofing
                if 'net.ipv4.conf.all.rp_filter=1' in linhas and \
                        'net.ipv4.conf.default.rp_filter=1' in linhas:
                    msg = 'Proteção contra IP Spoofing desativada'
                    check_results['ok'].append(msg)
                else:
                    msg = 'Proteção contra IP Spoofing ativada'
                    check_results['low'].append(msg)

                #Ignorar requisicao ICMP de broadcast
                if 'net.ipv4.icmp_echo_ignore_broadcasts=1' in linhas:
                    msg = 'Requisição ICMP de broadcast ignorada'
                    check_results['ok'].append(msg)
                else:
                    msg = 'Requisição ICMP de broadcast não é ignorada'
                    check_results['low'].append(msg)

                #desativar IP Source Routing
                if 'net.ipv4.conf.all.accept_source_route=0' in linhas and \
                        'net.ipv4.conf.default.accept_source_route=0'in linhas:
                    msg = 'IP Source Routing para IPV4 desativado'
                    check_results['ok'].append(msg)
                else:
                    msg = 'IP Source Routing para IPV4 ativado'
                    check_results['low'].append(msg)

                if 'net.ipv6.conf.all.accept_source_route=0' in linhas and \
                        'net.ipv6.conf.default.accept_source_route=0'in linhas:
                    msg = 'IP Source Routing para IPV6 desativado'
                    check_results['ok'].append(msg)
                else:
                    msg = 'IP Source Routing para IPV6 ativado'
                    check_results['low'].append(msg)

                #evita que a maquina envie pacotes ICMP com redirecionamentos
                if 'net.ipv4.conf.all.send_redirects=0' in linhas and \
                        'net.ipv4.conf.default.send_redirects=0' in linhas:
                    msg = 'Envio de ICMP com redirecionamento está desativado'
                    check_results['ok'].append(msg)
                else:
                    msg = 'Envio de ICMP com redirecionamento está ativado'
                    check_results['low'].append(msg)

                #Protecao de TCP SYN Cookie
                if 'net.ipv4.tcp_syncookies=1' in linhas:
                    msg = 'TCP SYN Cookie Protection está ativada'
                    check_results['ok'].append(msg)
                else:
                    msg = 'TCP SYN Cookie Protection não está ativada'
                    check_results['low'].append(msg)

                #Evita redirecionamento ICMP
                if 'net.ipv4.conf.all.accept_redirects=0' in linhas and \
                        'net.ipv4.conf.default.accept_redirects=0' in linhas:
                    msg = 'Está ignorando redirecionamento ICMP no IPV4'
                    check_results['ok'].append(msg)
                else:
                    msg = 'Não está ignorando redirecionamento ICMP no IPV4'
                    check_results['low'].append(msg)

                if 'net.ipv6.conf.all.accept_redirects=0' in linhas and \
                        'net.ipv6.conf.default.accept_redirects=0' in linhas:
                    msg = 'Está ignorando redirecionamento ICMP no IPV6'
                    check_results['ok'].append(msg)
                else:
                    msg = 'Não está ignorando redirecionamento ICMP no IPV6'
                    check_results['low'].append(msg)

                #Verifica se a resposta do ping esta desativada
                if 'net.ipv4.icmp_echo_ignore_all=1' in linhas:
                    msg = 'Resposta ao ping está desativada'
                    check_results['ok'].append(msg)
                else:
                    msg = 'Resposta ao ping está ativada'
                    check_results['low'].append(msg)

        return check_results
