# -*- coding: utf-8 -*-

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

from .ownable_mixin import OwnableMixin

class OwnableLockableWriteMixin(OwnableMixin):
    """
"OwnableLockableWriteMixin" prevents write access to locked entries even
if the user would normally have the required permission.

:author:     direct Netware Group et al.
:copyright:  direct Netware Group - All rights reserved
:package:    pas
:subpackage: database_ownable
:since:      v0.2.00
:license:    https://www.direct-netware.de/redirect?licenses;gpl
             GNU General Public License 2
    """

    def is_manageable_for_user(self, user_id):
        """
Returns true if the entry is manageable for the given user ID.

:param user_id: User ID

:return: (bool) True if the entry is manageable for the given user ID
:since:  v0.2.00
        """

        _return = OwnableMixin.is_manageable_for_user(self, user_id)

        if (_return):
            entry_data = self.get_data_attributes("locked")

            if (entry_data['locked']):
                user_profile = self._get_user_profile(user_id)
                _return = (user_profile is not None and user_profile.is_type_or_higher("ad"))
            #
        #

        return _return
    #

    def is_writable_for_guest(self):
        """
Returns true if the entry is writable for guests.

:return: (bool) True if the entry is writable for guests
:since:  v0.2.00
        """

        _return = OwnableMixin.is_writable_for_guest(self)

        if (_return):
            entry_data = self.get_data_attributes("locked")
            _return = (not entry_data['locked'])
        #

        return _return
    #

    def is_writable_for_user(self, user_id):
        """
Returns if the entry is writable for the given user ID.

:param user_id: User ID

:return: (bool) True if the entry is writable for the given user ID
:since:  v0.2.00
        """

        _return = OwnableMixin.is_writable_for_user(self, user_id)

        if (_return):
            entry_data = self.get_data_attributes("locked")

            if (entry_data['locked']):
                user_profile = self._get_user_profile(user_id)
                _return = (user_profile is not None and user_profile.is_type_or_higher("ad"))
            #
        #

        return _return
    #
#
