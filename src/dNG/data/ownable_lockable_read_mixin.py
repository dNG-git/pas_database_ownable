# -*- coding: utf-8 -*-
##j## BOF

"""
direct PAS
Python Application Services
----------------------------------------------------------------------------
(C) direct Netware Group - All rights reserved
https://www.direct-netware.de/redirect?pas;database_ownable

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
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
----------------------------------------------------------------------------
https://www.direct-netware.de/redirect?licenses;gpl
----------------------------------------------------------------------------
#echo(pasDatabaseOwnableVersion)#
#echo(__FILEPATH__)#
"""

from .ownable_lockable_write_mixin import OwnableLockableWriteMixin

class OwnableLockableReadMixin(OwnableLockableWriteMixin):
#
	"""
"OwnableLockableReadMixin" prevents read (and write) access to locked
entries even if the user would normally have have the required permission.

:author:     direct Netware Group et al.
:copyright:  direct Netware Group - All rights reserved
:package:    pas
:subpackage: database_ownable
:since:      v0.2.00
:license:    https://www.direct-netware.de/redirect?licenses;gpl
             GNU General Public License 2
	"""

	def is_readable_for_guest(self):
	#
		"""
Returns true if the entry is readable for guests.

:return: (bool) True if the entry is readable for guests
:since:  v0.2.00
		"""

		_return = OwnableLockableWriteMixin.is_readable_for_guest(self)

		if (_return):
		#
			entry_data = self.get_data_attributes("locked")
			_return = (not entry_data['locked'])
		#

		return _return
	#

	def is_readable_for_user(self, user_id):
	#
		"""
Returns true if the entry is readable for the given user ID.

:param user_id: User ID

:return: (bool) True if the entry is readable for the given user ID
:since:  v0.2.00
		"""

		entry_data = self.get_data_attributes("locked")

		return (False
		        if (entry_data['locked'] and (not self.is_manageable_for_user(user_id))) else
		        OwnableLockableWriteMixin.is_readable_for_user(self, user_id)
		       )
	#
#

##j## EOF