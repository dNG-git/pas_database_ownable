# -*- coding: utf-8 -*-
##j## BOF

"""
dNG.pas.data.OwnableMixin
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

from dNG.pas.data.user.profile import Profile

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

	def __init__(self):
	#
		"""
Constructor __init__(OwnableMixin)

:since: v0.1.00
		"""

		self.permission_cache = None
		"""
Cached document permissions
		"""
	#

	def _get_permissions(self, cache_id):
	#
		"""
Return the list of permission rules based on the given cache ID.

:param cache_id: Permission cache ID

:return: (dict) Dict of permissions
:since:  v0.1.00
		"""

		self._init_permission_cache()
		return (self.permission_cache[cache_id] if (cache_id in self.permission_cache) else { })
	#

	def _get_permissions_group(self, group_id):
	#
		"""
Return the list of group permission rules based on the given group ID.

:param group_id: Group ID

:return: (dict) Dict of permissions
:since:  v0.1.00
		"""

		return self._get_permissions("g_{0}".format(group_id))
	#

	def _get_permissions_user(self, user_id):
	#
		"""
Return the list of user permission rules based on the given user ID.

:param user_id: User ID

:return: (dict) Dict of permissions
:since:  v0.1.00
		"""

		return self._get_permissions("u_{0}".format(user_id))
	#

	def _init_permission_cache(self):
	#
		"""
Initializes the permission cache.

:since: v0.1.00
		"""

		if (self.permission_cache == None):
		#
			with self:
			#
				self.permission_cache = { }

				for acl_entry in self.local.db_instance.rel_acl:
				#
					permissions = { }
					for permission in acl_entry.rel_permissions: permissions[permission.name] = permission.permitted

					if (len(permissions) > 0): self.permission_cache["{0}_{1}".format(acl_entry.owner_type, acl_entry.owner_id)] = permissions
				#
			#
		#
	#

	def is_manageable_for_user(self, user_id):
	#
		"""
Returns if the entry is manageable for the given user ID.

:return: (bool) True if the entry is manageable for the given user ID
:since:  v0.1.00
		"""

		_return = False
		user_profile = (None if (_return or user_id == None) else Profile.load_id(user_id))

		if (user_profile != None and user_profile.is_valid()):
		#
			if (user_profile.is_type("ad")): _return = True

			if (not _return):
			#
				permissions = self._get_permissions_user(user_id)
				if ("moderate" in permissions and user_profile.is_type("mo")): _return = True
			#
		#

		return _return
	#

	def is_readable_for_guest(self):
	#
		"""
Returns if the entry is readable for guests.

:return: (bool) True if the entry is readable for guests
:since:  v0.1.00
		"""

		document_data = self.data_get("locked", "public_permission")

		return (
			(not document_data['locked']) and
			(document_data['public_permission'] == "r" or document_data['public_permission'] == "w")
		)
	#

	def is_readable_for_user(self, user_id):
	#
		"""
Returns if the entry is readable for the given user ID.

:return: (bool) True if the entry is readable for the given user ID
:since:  v0.1.00
		"""

		_return = self.is_readable_for_guest()
		user_profile = (None if (_return or user_id == None) else Profile.load_id(user_id))

		if (user_profile != None and user_profile.is_valid()):
		#
			if (user_profile.is_type("ad")): _return = True

			if (not _return):
			#
				permissions = self._get_permissions_user(user_id)

				if ("readable" in permissions): _return = True
				elif ("moderate" in permissions and user_profile.is_type("mo")): _return = True
			#
		#

		return _return
	#

	def is_writable_for_guest(self):
	#
		"""
Returns if the entry is writable for guests.

:return: (bool) True if the entry is writable for guests
:since:  v0.1.00
		"""

		document_data = self.data_get("locked", "public_permission")
		return ((not document_data['locked']) and (document_data['public_permission'] == "w"))
	#

	def is_writable_for_user(self, user_id):
	#
		"""
Returns if the entry is writable for the given user ID.

:return: (bool) True if the entry is writable for the given user ID
:since:  v0.1.00
		"""

		_return = self.is_writable_for_guest()
		user_profile = (None if (_return or user_id == None) else Profile.load_id(user_id))

		if (user_profile != None and user_profile.is_valid()):
		#
			if (user_profile.is_type("ad")): _return = True

			if (not _return):
			#
				permissions = self._get_permissions_user(user_id)

				if ("writable" in permissions): _return = True
				elif ("moderate" in permissions and user_profile.is_type("mo")): _return = True
			#
		#

		return _return
	#

	def reset_permission_cache(self):
	#
		"""
Resets the permission cache.

:return: (object) SQLalchemy relationship description
:since:  v0.1.00
		"""

		if (self.permission_cache == None):
		#
			with self:
			#
				self.permission_cache = { }

				for acl_entry in self.local.db_instance.rel_acl:
				#
					permissions = { }
					for permission in acl_entry.rel_permissions: permissions[permission.name] = permission.permitted

					if (len(permissions) > 0): self.permission_cache["{0}_{1}".format(acl_entry.owner_type, acl_entry.owner_id)] = permissions
				#
			#
		#
	#

	@staticmethod
	def _get_session_user_id(session):
	#
		"""
Relation to TextEntry (backref is set as "rel_referer")

:return: (object) SQLalchemy relationship description
:since:  v0.1.00
		"""

		return (None if (session == None) else session.get_user_id())
	#

	@staticmethod
	def is_manageable_for_session_user(_entry, session):
	#
		"""
Relation to TextEntry (backref is set as "rel_referer")

:return: (object) SQLalchemy relationship description
:since:  v0.1.00
		"""

		return _entry.is_manageable_for_user(OwnableMixin._get_session_user_id(session))
	#

	@staticmethod
	def is_readable_for_session_user(_entry, session):
	#
		"""
Relation to TextEntry (backref is set as "rel_referer")

:return: (object) SQLalchemy relationship description
:since:  v0.1.00
		"""

		return _entry.is_readable_for_user(OwnableMixin._get_session_user_id(session))
	#

	@staticmethod
	def is_writable_for_session_user(_entry, session):
	#
		"""
Relation to TextEntry (backref is set as "rel_referer")

:return: (object) SQLalchemy relationship description
:since:  v0.1.00
		"""

		return _entry.is_writable_for_user(OwnableMixin._get_session_user_id(session))
	#
#

##j## EOF