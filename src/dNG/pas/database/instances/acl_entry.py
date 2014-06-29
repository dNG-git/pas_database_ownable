# -*- coding: utf-8 -*-
##j## BOF

"""
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
"""

from sqlalchemy.orm import relationship
from sqlalchemy.schema import Column
from sqlalchemy.types import CHAR, VARCHAR
from uuid import uuid4 as uuid

from .abstract import Abstract
from .permission import Permission

class AclEntry(Abstract):
#
	"""
"TextEntry" contains the database representation for a text entry.

:author:     direct Netware Group
:copyright:  direct Netware Group - All rights reserved
:package:    pas
:subpackage: database_ownable
:since:      v0.1.00
:license:    http://www.direct-netware.de/redirect.py?licenses;gpl
             GNU General Public License 2
	"""

	# pylint: disable=invalid-name

	__tablename__ = "{0}_acl".format(Abstract.get_table_prefix())
	"""
SQLAlchemy table name
	"""

	id = Column(VARCHAR(32), primary_key = True)
	"""
owner_list.id
	"""
	owned_id = Column(VARCHAR(32), index = True, nullable = False)
	"""
owner_list.owned_id
	"""
	owner_id = Column(VARCHAR(32), index = True, nullable = False)
	"""
owner_list.owner_id
	"""
	owner_type = Column(CHAR(1), server_default = "u", nullable = False)
	"""
owner_list.owner_type
	"""

	rel_permissions = relationship(Permission)
	"""
Relation to Permission
	"""

	def __init__(self, *args, **kwargs):
	#
		"""
Constructor __init__(AclEntry)

:since: v0.1.00
		"""

		Abstract.__init__(self, *args, **kwargs)
		if (self.id == None): self.id = uuid().hex
	#
#

##j## EOF