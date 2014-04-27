# -*- coding: utf-8 -*-
##j## BOF

"""
dNG.pas.database.instances.OwnableMixin
"""
"""n// NOTE
----------------------------------------------------------------------------
direct PAS
Python Application Services
----------------------------------------------------------------------------
(C) direct Netware Group - All rights reserved
http://www.direct-netware.de/redirect.py?pas;database_ownable

The following license agreement remains valid unless any additions or
changes are being made by direct Netware Group in a written form.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc.,
59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
----------------------------------------------------------------------------
http://www.direct-netware.de/redirect.py?licenses;gpl
----------------------------------------------------------------------------
#echo(pasDatabaseOwnableVersion)#
#echo(__FILEPATH__)#
----------------------------------------------------------------------------
NOTE_END //n"""

from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import foreign, relationship, remote

from .acl_entry import AclEntry

class OwnableMixin(object):
#
	"""
The "OwnableMixin" class provides a relationship to a list of owners for the
given entry ID.

:author:     direct Netware Group
:copyright:  direct Netware Group - All rights reserved
:package:    pas
:subpackage: database_ownable
:since:      v0.1.00
:license:    http://www.direct-netware.de/redirect.py?licenses;gpl
             GNU General Public License 2
	"""

	@declared_attr
	def rel_acl(self):
	#
		"""
Relation to AclEntry (backref is set as "rel_referer")

:return: (object) SQLAlchemy relationship description
:since:  v0.1.00
		"""

		return relationship(AclEntry, primaryjoin = (foreign(self.id) == remote(AclEntry.owned_id)), uselist = True)
	#
#

##j## EOF