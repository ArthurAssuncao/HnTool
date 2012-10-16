Modules
==========================

The main HnTool program (core.py) runs a list of rules defined in __files__
and __services__.

 * __files__ :
	defines the rules which process simple files and configs.

 * __services__ :
	defines the rules which checks the security on services and
	daemons.

Once your module is finalized, remember to add it to the appropriate array
(__files__ or __services__) defined in hntool/__init__.py

rule.py
----------------------------------

.. automodule:: rule
   :members:

apache.py
----------------------------------

.. automodule:: apache
   :members:

authentication.py
----------------------------------

.. automodule:: authentication
   :members:

compiladores.py
----------------------------------

.. automodule:: compiladores
   :members:

filesystems.py
----------------------------------

.. automodule:: filesystems
   :members:

grub.py
----------------------------------

.. automodule:: grub
   :members:

limits.py
----------------------------------

.. automodule:: limits
   :members:

log.py
----------------------------------

.. automodule:: log
   :members:

php.py
----------------------------------

.. automodule:: php
   :members:

ports.py
----------------------------------

.. automodule:: ports
   :members:

postgresql.py
----------------------------------

.. automodule:: postgresql
   :members:

proftpd.py
----------------------------------

.. automodule:: proftpd
   :members:

remote.py
----------------------------------

.. automodule:: remote
   :members:

securetty.py
----------------------------------

.. automodule:: securetty
   :members:

ssh.py
----------------------------------

.. automodule:: ssh
   :members:

sysctl.py
----------------------------------

.. automodule:: sysctl
   :members:

util.py
----------------------------------

.. automodule:: util
   :members:

vsftpd.py
----------------------------------

.. automodule:: vsftpd
   :members:

xinetd.py
----------------------------------

.. automodule:: xinetd
   :members:

