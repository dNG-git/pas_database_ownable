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
59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
----------------------------------------------------------------------------
https://www.direct-netware.de/redirect?licenses;gpl
----------------------------------------------------------------------------
#echo(pasDatabaseOwnableVersion)#
#echo(__FILEPATH__)#
"""

from dNG.data.acl.entry import Entry
from dNG.database.nothing_matched_exception import NothingMatchedException
from dNG.module.named_loader import NamedLoader
from dNG.runtime.type_exception import TypeException
from dNG.runtime.value_exception import ValueException

try: from dNG.data.session.implementation import Implementation as Session
except ImportError: Session = None

class OwnableMixin(object):
#
	"""
The "OwnableMixin" class provides a relationship to a list of permission
owners for the given entry ID.

:author:     direct Netware Group et al.
:copyright:  direct Netware Group - All rights reserved
:package:    pas
:subpackage: database_ownable
:since:      v0.2.00
:license:    https://www.direct-netware.de/redirect?licenses;gpl
             GNU General Public License 2
	"""

	READABLE = "r"
	"""
Readable permission
	"""
	NO_ACCESS = ""
	"""
No access permission
	"""
	WRITABLE = "w"
	"""
Writable permission
	"""

	def __init__(self):
	#
		"""
Constructor __init__(OwnableMixin)

:since: v0.2.00
		"""

		self.inherited_permission_guest_max = OwnableMixin.WRITABLE
		"""
Maximum allowed default permission for guests to be assigned by inheritance.
		"""
		self.inherited_permission_user_max = OwnableMixin.WRITABLE
		"""
Maximum allowed default permission for users to be assigned by inheritance.
		"""
		self.permission_cache = None
		"""
Cached permissions
		"""
		self.permission_user_profile_cache = { }
		"""
User profile cache
		"""
		self.permission_user_id = None
		"""
User ID to check permissions for
		"""
	#

	def add_acl(self, acl_entry):
	#
		"""
Add the given ACL entry instance.

:param acl_entry: ACL entry instance

:since: v0.2.00
		"""

		# pylint: disable=protected-access

		if (self.log_handler is not None): self.log_handler.debug("#echo(__FILEPATH__)# -{0!r}.add_entry()- (#echo(__LINE__)#)", self, context = "pas_database")

		if (isinstance(acl_entry, Entry)):
		#
			with self:
			#
				if (acl_entry.get_owned_id() == self.get_id()):
				#
					self.local.db_instance.rel_acl.append(acl_entry._get_db_instance())
				#
			#
		#
	#

	def _copy_acl_entries_from_instance(self, instance):
	#
		"""
Copies default permission settings from the given instance.

:param instance: OwnableMixin implementing instance

:since: v0.2.00
		"""

		if (self.log_handler is not None): self.log_handler.debug("#echo(__FILEPATH__)# -{0!r}._copy_acl_entries_from_instance()- (#echo(__LINE__)#)", self, context = "pas_database")

		if (not isinstance(instance, OwnableMixin)): raise ValueException("Can't copy ACL entries from a non-ownable instance")

		with instance, self, self.local.connection.no_autoflush:
		#
			rel_acl = instance.get_data_attributes("rel_acl")['rel_acl']

			if (rel_acl is not None and len(rel_acl) > 0):
			#
				for source_acl_entry in rel_acl:
				#
					source_acl_entry_data = source_acl_entry.get_data_attributes("owner_id", "owner_type")

					acl_entry = Entry()

					acl_entry.set_data_attributes(owned_id = self.get_id(),
					                              owner_id = source_acl_entry_data['owner_id'],
					                              owner_type = source_acl_entry_data['owner_type']
					                             )

					permissions = source_acl_entry.get_permissions_dict()
					for permission_name in permissions: acl_entry.set_permission(permission_name, permissions['permission_name'])

					acl_entry.save()

					self.add_acl(acl_entry)
				#
			#
		#
	#

	def _copy_default_permission_settings_from_instance(self, instance):
	#
		"""
Copies default permission settings from the given instance.

:param instance: OwnableMixin implementing instance

:since: v0.2.00
		"""

		if (self.log_handler is not None): self.log_handler.debug("#echo(__FILEPATH__)# -{0!r}._copy_default_permissions_from_instance()- (#echo(__LINE__)#)", self, context = "pas_database")

		if (not isinstance(instance, OwnableMixin)): raise ValueException("Can't copy default permissions from a non-ownable instance")

		with self:
		#
			instance_data = instance.get_data_attributes("owner_type", "guest_permission", "user_permission")

			if (self.local.db_instance.owner_type is None): self.local.db_instance.owner_type = instance_data['owner_type']

			if (self.local.db_instance.guest_permission is None):
			#
				guest_permission = self._ensure_max_inherited_permission(self.inherited_permission_guest_max, instance_data['guest_permission'])
				self.local.db_instance.guest_permission = guest_permission
			#

			if (self.local.db_instance.user_permission is None):
			#
				user_permission = self._ensure_max_inherited_permission(self.inherited_permission_user_max, instance_data['user_permission'])
				self.local.db_instance.user_permission = user_permission
			#
		#
	#

	def _ensure_max_inherited_permission(self, inherited_permission_max, permission):
	#
		"""
Ensure that the given permission is the same or below the defined maximum
allowed for the entry.

:param inherited_permission_max: Maximum permission inherited
:param permission: Permission to check and adjust

:return: (str) Permission character
:since:  v0.2.00
		"""

		_return = permission

		if (inherited_permission_max == OwnableMixin.READABLE): _return = OwnableMixin.READABLE
		elif (inherited_permission_max == OwnableMixin.NO_ACCESS): _return = OwnableMixin.NO_ACCESS

		return _return
	#

	def _get_permissions(self, cache_id):
	#
		"""
Returns the list of permission rules based on the given cache ID.

:param cache_id: Permission cache ID

:return: (dict) Dict of permissions
:since:  v0.2.00
		"""

		self._init_permission_cache()
		return (self.permission_cache[cache_id] if (cache_id in self.permission_cache) else { })
	#

	def _get_permissions_group(self, group_id):
	#
		"""
Returns the list of group permission rules based on the given group ID.

:param group_id: Group ID

:return: (dict) Dict of permissions
:since:  v0.2.00
		"""

		return self._get_permissions("g_{0}".format(group_id))
	#

	def _get_permissions_user(self, user_id):
	#
		"""
Returns the list of user permission rules based on the given user ID.

:param user_id: User ID

:return: (dict) Dict of permissions
:since:  v0.2.00
		"""

		return self._get_permissions("u_{0}".format(user_id))
	#

	def get_permission_user_id(self):
	#
		"""
Returns the user ID to check permissions for.

:return: (str) User ID
:since:  v0.2.00
		"""

		return self.permission_user_id
	#

	def _get_user_profile(self, user_id):
	#
		"""
Returns the user profile instance for the given user ID.

:param user_id: User ID

:return: (object) User profile instance; None if not found
:since:  v0.2.00
		"""

		_return = None

		if (user_id is not None):
		#
			_return = self.permission_user_profile_cache.get(user_id)

			if (_return is None):
			#
				user_profile_class = NamedLoader.get_class("dNG.data.user.Profile")

				_return = (None if (user_profile_class is None) else user_profile_class.load_id(user_id))
				if (_return is not None): self.permission_user_profile_cache[user_id] = _return
			#

			if (_return is not None and (not _return.is_valid())): _return = None
		#

		return _return
	#

	def _init_permission_cache(self):
	#
		"""
Initializes the permission cache.

:since: v0.2.00
		"""

		if (self.permission_cache is None):
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

	def is_manageable(self):
	#
		"""
Returns true if the entry is manageable for the defined user.

:return: (bool) True if the entry is manageable for the defined user
:since:  v0.2.00
		"""

		return self.is_manageable_for_user(self.permission_user_id)
	#

	def is_manageable_for_session_user(self, session):
	#
		"""
Returns true if the entry is manageable for the user identified by the given
session.

:param session: Session instance

:return: (bool) True if the entry is manageable for the given session user
:since:  v0.2.00
		"""

		return self.is_manageable_for_user(None if (Session is None) else Session.get_session_user_id(session))
	#

	def is_manageable_for_user(self, user_id):
	#
		"""
Returns true if the entry is manageable for the given user ID.

:param user_id: User ID

:return: (bool) True if the entry is manageable for the given user ID
:since:  v0.2.00
		"""

		_return = False

		user_profile = self._get_user_profile(user_id)

		if (user_profile is not None):
		#
			if (user_profile.is_type("ad")): _return = True
			else:
			#
				permissions = self._get_permissions_user(user_id)
				if ("moderate" in permissions and user_profile.is_type("mo")): _return = True
			#
		#

		return _return
	#

	def is_readable(self):
	#
		"""
Returns true if the entry is readable for the defined user.

:return: (bool) True if the entry is readable for the defined user
:since:  v0.2.00
		"""

		return self.is_readable_for_user(self.permission_user_id)
	#

	def is_readable_for_guest(self):
	#
		"""
Returns true if the entry is readable for guests.

:return: (bool) True if the entry is readable for guests
:since:  v0.2.00
		"""

		entry_data = self.get_data_attributes("guest_permission")

		return (entry_data['guest_permission'] == OwnableMixin.READABLE
		        or entry_data['guest_permission'] == OwnableMixin.WRITABLE
		       )
	#

	def is_readable_for_session_user(self, session):
	#
		"""
Returns true if the entry is readable for the user identified by the given
session.

:param session: Session instance

:return: (bool) True if the entry is readable for the given session user
:since:  v0.2.00
		"""

		return self.is_readable_for_user(None if (Session is None) else Session.get_session_user_id(session))
	#

	def is_readable_for_user(self, user_id):
	#
		"""
Returns true if the entry is readable for the given user ID.

:param user_id: User ID

:return: (bool) True if the entry is readable for the given user ID
:since:  v0.2.00
		"""

		_return = self.is_readable_for_guest()

		if (not _return):
		#
			user_profile = self._get_user_profile(user_id)

			if (user_profile is not None):
			#
				entry_data = self.get_data_attributes("user_permission")

				if (user_profile.is_type("ad")): _return = True
				elif (entry_data['user_permission'] == OwnableMixin.READABLE
				      or entry_data['user_permission'] == OwnableMixin.WRITABLE
				     ): _return = True

				if (not _return):
				#
					permissions = self._get_permissions_user(user_id)

					if ("readable" in permissions): _return = True
					elif ("moderate" in permissions and user_profile.is_type("mo")): _return = True
					elif ("writable" in permissions): _return = True
				#
			#
		#

		return _return
	#

	def is_writable(self):
	#
		"""
Returns true if the entry is writable for the defined user.

:return: (bool) True if the entry is writable for the defined user
:since:  v0.2.00
		"""

		return self.is_writable_for_user(self.permission_user_id)
	#

	def is_writable_for_guest(self):
	#
		"""
Returns true if the entry is writable for guests.

:return: (bool) True if the entry is writable for guests
:since:  v0.2.00
		"""

		entry_data = self.get_data_attributes("guest_permission")
		return (entry_data['guest_permission'] == OwnableMixin.WRITABLE)
	#

	def is_writable_for_session_user(self, session):
	#
		"""
Returns true if the entry is writable for the user identified by the given
session.

:param session: Session instance

:return: (bool) True if the entry is writable for the given session user
:since:  v0.2.00
		"""

		return self.is_writable_for_user(None if (Session is None) else Session.get_session_user_id(session))
	#

	def is_writable_for_user(self, user_id):
	#
		"""
Returns if the entry is writable for the given user ID.

:param user_id: User ID

:return: (bool) True if the entry is writable for the given user ID
:since:  v0.2.00
		"""

		_return = self.is_writable_for_guest()

		if (not _return):
		#
			user_profile = self._get_user_profile(user_id)

			if (user_profile is not None):
			#
				entry_data = self.get_data_attributes("user_permission")

				if (user_profile.is_type("ad")): _return = True
				elif (entry_data['user_permission'] == OwnableMixin.WRITABLE): _return = True

				if (not _return):
				#
					permissions = self._get_permissions_user(user_id)

					if ("writable" in permissions): _return = True
					elif ("moderate" in permissions and user_profile.is_type("mo")): _return = True
				#
			#
		#

		return _return
	#

	def reset_permission_cache(self):
	#
		"""
Resets the permission cache.

:return: (object) SQLAlchemy relationship description
:since:  v0.2.00
		"""

		self.permission_cache = None
		self.permission_user_profile_cache.clear()
	#

	def set_max_inherited_permissions(self, inherited_permission_guest_max, inherited_permission_user_max):
	#
		"""
Sets the maximum permissions for guests and users if inherited from a parent
source.

:param inherited_permission_guest_max: Maximum permission for guests
:param inherited_permission_user_max: Maximum permission for users

:since: v0.2.02
		"""

		self.inherited_permission_guest_max = inherited_permission_guest_max
		self.inherited_permission_user_max = inherited_permission_user_max
	#

	def set_permission_session(self, session):
	#
		"""
Sets the session user ID to check permissions for.

:param session: Session instance

:since: v0.2.00
		"""

		if (Session is None): raise TypeException("Given session instance can not be verified")
		self.set_permission_user_id(Session.get_session_user_id(session))
	#

	def set_permission_user_id(self, user_id):
	#
		"""
Sets the user ID to check permissions for.

:param user_id: User ID

:since: v0.2.00
		"""

		self.permission_user_id = user_id
	#

	def set_writable(self):
	#
		"""
Changes the ACL permission of the entry to be writable by the defined user.

:since: v0.2.00
		"""

		self.set_writable_for_user(self.permission_user_id)
	#

	def set_writable_if_logged_in(self):
	#
		"""
Changes the ACL permission of the entry to be writable by the defined logged
in user.

:since: v0.2.00
		"""

		if (self.permission_user_id is not None):
		#
			self.set_writable_for_user(self.permission_user_id)
		#
	#

	def set_writable_for_session_user(self, session):
	#
		"""
Changes the ACL permission of the entry to be writable by the user
identified by the given session.

:param session: Session instance

:since: v0.2.00
		"""

		user_id = (None if (Session is None) else Session.get_session_user_id(session))
		self.set_writable_for_user(user_id)
	#

	def set_writable_for_user(self, user_id):
	#
		"""
Changes the ACL permission of the entry to be writable by the given user ID.

:param user_id: User ID

:since: v0.2.00
		"""

		if (user_id is None): raise ValueException("Permissions can only be set for individual users")

		if (not self.is_writable_for_user(user_id)):
		#
			with self:
			#
				if (self.permission_cache is None): self._init_permission_cache()

				acl_id = "u_{0}".format(user_id)

				try: acl_entry = Entry.load_acl_id(self.get_id(), acl_id)
				except NothingMatchedException:
				#
					acl_entry = Entry()

					acl_entry.set_data_attributes(owned_id = self.get_id(),
					                              owner_id = user_id,
					                              owner_type = "u"
					                             )

					self.add_acl(acl_entry)
					self.permission_cache[acl_id] = { }
				#

				if ("readable" in self.permission_cache[acl_id]):
				#
					acl_entry.unset_permission("readable")
					del(self.permission_cache[acl_id]['readable'])
				#

				acl_entry.set_permission("writable")
				self.permission_cache[acl_id]['writable'] = True
			#
		#
	#
#

##j## EOF