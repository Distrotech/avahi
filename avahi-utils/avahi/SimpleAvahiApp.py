#!/usr/bin/python
# -*-python-*-
# $Id: $

# This file is part of avahi.
#
# avahi is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# avahi is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with avahi; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA.

import sys, getopt
import avahi, gobject, dbus, avahi.ServiceTypeDatabase

try:
    import dbus.glib
except ImportError, e:
    pass

class SimpleAvahiApp:
    def __init__(self):
        self.domain = None
        self.stype = "_ssh._tcp"
        self.service_type_browsers = {}
        self.service_browsers = {}
        self.service_type_db = avahi.ServiceTypeDatabase.ServiceTypeDatabase()
        self.bus = dbus.SystemBus()
        self.server = dbus.Interface(self.bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER), avahi.DBUS_INTERFACE_SERVER)

        if self.domain is None:
            # Explicitly browse .local
            self.browse_domain(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, "local")

            # Browse for other browsable domains
            db = dbus.Interface(self.bus.get_object(avahi.DBUS_NAME, self.server.DomainBrowserNew(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, "", avahi.DOMAIN_BROWSER_BROWSE)), avahi.DBUS_INTERFACE_DOMAIN_BROWSER)
            db.connect_to_signal('ItemNew', self.new_domain)

        else:
            # Just browse the domain the user wants us to browse
            self.browse_domain(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, self.domain)

        
    def siocgifname(self, interface):
         if interface <= 0:
             return "any"
         else:
             return self.server.GetNetworkInterfaceNameByIndex(interface)

    def lookup_service_type(self, stype):
        try:
            return self.service_type_db[stype]
        except KeyError:
            return "n/a"

    def service_resolved(self, interface, protocol, name, stype, domain, host, aprotocol, address, port, txt):
        print "Service data for service '%s' of type '%s' (%s) in domain '%s' on %s.%i:" % (name, stype, self.lookup_service_type(stype), domain, self.siocgifname(interface), protocol)
        print "\tHost %s (%s), port %i, TXT data: %s" % (host, address, port, avahi.txt_array_to_string_array(txt))

    def print_error(self, err):
        print "Error:", str(err)

    def new_service(self, interface, protocol, name, stype, domain):
        print "Found service '%s' of type '%s' (%s) in domain '%s' on %s.%i." % (name, stype, self.lookup_service_type(stype), domain, self.siocgifname(interface), protocol)
        
        # Asynchronous resolving
        self.server.ResolveService(interface, protocol, name, stype, domain, avahi.PROTO_UNSPEC, reply_handler=self.service_resolved, error_handler=self.print_error)

    def remove_service(self, interface, protocol, name, stype, domain):
        print "Service '%s' of type '%s' (%s) in domain '%s' on %s.%i disappeared." % (name, stype, self.lookup_service_type(stype), domain, self.siocgifname(interface), protocol)
 
    def new_service_type(self, interface, protocol, stype, domain):
        # Are we already browsing this domain for this type? 
        if self.service_browsers.has_key((interface, protocol, stype, domain)):
            return
        
        print "Browsing for services of type '%s' (%s) in domain '%s' on %s.%i ..." % (stype, self.lookup_service_type(stype), domain, self.siocgifname(interface), protocol)
        
        b = dbus.Interface(self.bus.get_object(avahi.DBUS_NAME, self.server.ServiceBrowserNew(interface, protocol, stype, domain)), avahi.DBUS_INTERFACE_SERVICE_BROWSER)
        b.connect_to_signal('ItemNew', self.new_service)
        b.connect_to_signal('ItemRemove', self.remove_service)
        
        self.service_browsers[(interface, protocol, stype, domain)] = b

    def browse_domain(self, interface, protocol, domain):
        print "browse_domain"
        # Are we already browsing this domain?
        if self.service_type_browsers.has_key((interface, protocol, domain)):
            return
        
        if self.stype is None:
            print "Browsing domain '%s' on %s.%i ..." % (domain, self.siocgifname(interface), protocol)
            
            b = dbus.Interface(self.bus.get_object(avahi.DBUS_NAME, self.server.ServiceTypeBrowserNew(interface, protocol, domain)), avahi.DBUS_INTERFACE_SERVICE_TYPE_BROWSER)
            b.connect_to_signal('ItemNew', self.new_service_type)
            
            self.service_type_browsers[(interface, protocol, domain)] = b
        else:
            self.new_service_type(interface, protocol, self.stype, domain)

    def new_domain(self, interface, protocol, domain):
        # We browse for .local anyway...
        if domain != "local":
            self.browse_domain(interface, protocol, domain)

if __name__ == "__main__":
    print "__main__"
    sb = SimpleAvahiApp()

    try:
        gobject.MainLoop().run()
    except KeyboardInterrupt, k:
        pass

