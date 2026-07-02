#!/usr/bin/env python3
"""
ONVIF Device Enumerator
Comprehensive enumeration of ONVIF-compatible IP cameras/NVRs.
For authorized security testing and network administration.

Packaged by Jon 'GainSec' Gaines as a standalone research utility.
"""

import argparse
import sys
import json
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
import socket
from datetime import datetime
from urllib.parse import urlparse, urlunparse

try:
    from onvif import ONVIFCamera, ONVIFError
    from zeep.transports import Transport
    from requests import Session
except ImportError:
    print("[!] Missing dependency: pip install onvif-zeep")
    sys.exit(1)

# Set default socket timeout to prevent hangs on unresolvable hostnames
socket.setdefaulttimeout(10)


@dataclass
class ONVIFTarget:
    ip: str
    port: int = 80
    username: str = "admin"
    password: str = "admin"
    wsdl_dir: Optional[str] = None


@dataclass
class EnumerationResults:
    """Store all enumeration results."""
    target: str = ""
    device_info: Dict = field(default_factory=dict)
    capabilities: Dict = field(default_factory=dict)
    services: List = field(default_factory=list)
    scopes: List = field(default_factory=list)
    network: Dict = field(default_factory=dict)
    profiles: List = field(default_factory=list)
    video_sources: List = field(default_factory=list)
    audio_sources: List = field(default_factory=list)
    video_encoders: List = field(default_factory=list)
    audio_encoders: List = field(default_factory=list)
    osds: List = field(default_factory=list)
    ptz: Dict = field(default_factory=dict)
    imaging: Dict = field(default_factory=dict)
    events: Dict = field(default_factory=dict)
    analytics: Dict = field(default_factory=dict)
    recording: Dict = field(default_factory=dict)
    search: Dict = field(default_factory=dict)
    replay: Dict = field(default_factory=dict)
    users: List = field(default_factory=list)
    certificates: List = field(default_factory=list)
    ip_filter: Dict = field(default_factory=dict)
    relay_outputs: List = field(default_factory=list)
    digital_inputs: List = field(default_factory=list)
    system: Dict = field(default_factory=dict)
    security: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}


class ONVIFEnumerator:
    """Comprehensive ONVIF device enumeration."""

    def __init__(self, target: ONVIFTarget):
        self.target = target
        self.camera = None
        self.results = EnumerationResults(target=f"{target.ip}:{target.port}")

        # Service caches
        self._device_service = None
        self._media_service = None
        self._media2_service = None
        self._ptz_service = None
        self._imaging_service = None
        self._events_service = None
        self._analytics_service = None
        self._recording_service = None
        self._search_service = None
        self._replay_service = None
        # Extended services
        self._doorcontrol_service = None
        self._accesscontrol_service = None
        self._thermal_service = None
        self._deviceio_service = None
        self._credential_service = None
        self._accessrules_service = None
        self._schedule_service = None
        self._receiver_service = None
        self._provisioning_service = None

    def _fix_service_url(self, url: str) -> str:
        """Force service URL to use target IP."""
        if not url:
            return url
        parsed = urlparse(url)
        if not parsed.hostname:
            return url

        # Always force target IP
        port = parsed.port if parsed.port else self.target.port
        new_netloc = f"{self.target.ip}:{port}"
        return urlunparse((parsed.scheme, new_netloc, parsed.path,
                          parsed.params, parsed.query, parsed.fragment))

    def _patch_service_urls(self):
        """Patch all service URLs in camera.xaddrs to use target IP."""
        if not hasattr(self.camera, 'xaddrs') or not self.camera.xaddrs:
            return

        patched = 0
        for service_ns, url in list(self.camera.xaddrs.items()):
            fixed_url = self._fix_service_url(url)
            if fixed_url != url:
                self.camera.xaddrs[service_ns] = fixed_url
                patched += 1

        if patched > 0:
            print(f"  [+] Patched {patched} service URL(s) to use {self.target.ip}")

    def _patch_service_binding(self, service):
        """Patch a service's binding address to use target IP."""
        if not service:
            return service
        try:
            # Patch ONVIFService.xaddr
            if hasattr(service, 'xaddr'):
                service.xaddr = self._fix_service_url(service.xaddr)

            # Patch zeep service proxy binding options
            if hasattr(service, '_binding_options') and 'address' in service._binding_options:
                service._binding_options['address'] = self._fix_service_url(service._binding_options['address'])

            # Patch ws_client (zeep client wrapper in python-onvif)
            if hasattr(service, 'ws_client'):
                ws = service.ws_client
                if hasattr(ws, '_binding_options') and 'address' in ws._binding_options:
                    ws._binding_options['address'] = self._fix_service_url(ws._binding_options['address'])

                # Patch zeep client's service binding operations
                if hasattr(ws, '_client') and hasattr(ws._client, 'wsdl'):
                    wsdl = ws._client.wsdl
                    if hasattr(wsdl, 'bindings'):
                        for binding in wsdl.bindings.values():
                            if hasattr(binding, '_operations'):
                                for op in binding._operations.values():
                                    if hasattr(op, 'location'):
                                        op.location = self._fix_service_url(op.location)
        except Exception:
            pass
        return service

    def connect(self) -> bool:
        """Establish connection to ONVIF device."""
        print(f"\n[*] Connecting to {self.target.ip}:{self.target.port}")
        try:
            # Create session with timeout
            session = Session()
            session.timeout = 10  # 10 second timeout

            # Create transport with timeout
            transport = Transport(session=session, timeout=10, operation_timeout=15)

            # Build kwargs - only include wsdl_dir if specified
            kwargs = {
                'host': self.target.ip,
                'port': self.target.port,
                'user': self.target.username,
                'passwd': self.target.password,
                'transport': transport,
            }
            if self.target.wsdl_dir:
                kwargs['wsdl_dir'] = self.target.wsdl_dir

            self.camera = ONVIFCamera(**kwargs)
            self._device_service = self.camera.devicemgmt

            # Fix service URLs if they contain unresolvable hostnames
            self._patch_service_urls()

            print("[+] Connected successfully")
            return True
        except ONVIFError as e:
            print(f"[-] ONVIF Error: {e}")
            return False
        except socket.timeout:
            print(f"[-] Connection timed out")
            return False
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False

    # =========================================================================
    # DEVICE SERVICE OPERATIONS
    # =========================================================================

    def get_device_info(self) -> dict:
        """Retrieve device information."""
        print("\n[*] Device Information")
        print("-" * 50)
        try:
            info = self._device_service.GetDeviceInformation()
            device_info = {
                "Manufacturer": getattr(info, 'Manufacturer', 'N/A'),
                "Model": getattr(info, 'Model', 'N/A'),
                "Firmware": getattr(info, 'FirmwareVersion', 'N/A'),
                "Serial": getattr(info, 'SerialNumber', 'N/A'),
                "Hardware": getattr(info, 'HardwareId', 'N/A'),
            }
            for key, value in device_info.items():
                print(f"  {key}: {value}")
            self.results.device_info = device_info
            return device_info
        except Exception as e:
            print(f"[-] Failed to get device info: {e}")
            return {}

    def get_wsdl_url(self) -> str:
        """Get WSDL URL from device."""
        print("\n[*] WSDL URL")
        print("-" * 50)
        try:
            wsdl = self._device_service.GetWsdlUrl()
            wsdl_url = getattr(wsdl, 'WsdlUrl', str(wsdl)) if hasattr(wsdl, 'WsdlUrl') else str(wsdl)
            print(f"  [+] WSDL: {wsdl_url}")
            self.results.system['wsdl_url'] = wsdl_url
            return wsdl_url
        except Exception as e:
            print(f"[-] Failed to get WSDL URL: {e}")
            return ""

    def get_capabilities(self) -> dict:
        """Enumerate device capabilities."""
        print("\n[*] Device Capabilities")
        print("-" * 50)
        try:
            caps = self._device_service.GetCapabilities({'Category': 'All'})
            capabilities = {}

            cap_types = [
                ('Analytics', ['XAddr', 'RuleSupport', 'AnalyticsModuleSupport']),
                ('Device', ['XAddr']),
                ('Events', ['XAddr', 'WSSubscriptionPolicySupport', 'WSPullPointSupport']),
                ('Imaging', ['XAddr']),
                ('Media', ['XAddr']),
                ('PTZ', ['XAddr']),
            ]

            for cap_name, attrs in cap_types:
                if hasattr(caps, cap_name) and getattr(caps, cap_name):
                    cap_obj = getattr(caps, cap_name)
                    capabilities[cap_name] = {attr: getattr(cap_obj, attr, None) for attr in attrs}
                    xaddr = getattr(cap_obj, 'XAddr', 'N/A')
                    print(f"  [+] {cap_name}: {xaddr}")

            # Extension capabilities
            if hasattr(caps, 'Extension') and caps.Extension:
                ext = caps.Extension
                ext_caps = ['Recording', 'Search', 'Replay', 'DeviceIO', 'Extensions']
                for ext_cap in ext_caps:
                    if hasattr(ext, ext_cap) and getattr(ext, ext_cap):
                        ext_obj = getattr(ext, ext_cap)
                        xaddr = getattr(ext_obj, 'XAddr', None)
                        if xaddr:
                            capabilities[ext_cap] = {'XAddr': xaddr}
                            print(f"  [+] {ext_cap}: {xaddr}")

            self.results.capabilities = capabilities
            return capabilities
        except Exception as e:
            print(f"[-] Failed to get capabilities: {e}")
            return {}

    def get_services(self) -> list:
        """Get available ONVIF services."""
        print("\n[*] Available Services")
        print("-" * 50)
        try:
            services = self._device_service.GetServices({'IncludeCapability': True})
            service_list = []

            for svc in services:
                namespace = getattr(svc, 'Namespace', 'Unknown')
                xaddr = getattr(svc, 'XAddr', 'Unknown')
                version = getattr(svc, 'Version', None)

                ver_str = ""
                if version:
                    major = getattr(version, 'Major', 0)
                    minor = getattr(version, 'Minor', 0)
                    ver_str = f" (v{major}.{minor})"

                svc_name = namespace.split('/')[-1] if namespace else 'Unknown'
                service_list.append({
                    'name': svc_name,
                    'namespace': namespace,
                    'xaddr': xaddr,
                    'version': ver_str.strip()
                })
                print(f"  [+] {svc_name}{ver_str}: {xaddr}")

            self.results.services = service_list
            return service_list
        except Exception as e:
            print(f"[-] Failed to get services: {e}")
            return []

    def get_service_capabilities(self) -> dict:
        """Get detailed service capabilities."""
        print("\n[*] Service Capabilities")
        print("-" * 50)
        try:
            caps = self._device_service.GetServiceCapabilities()
            svc_caps = {}

            # Network capabilities
            if hasattr(caps, 'Network') and caps.Network:
                net = caps.Network
                svc_caps['Network'] = {
                    'IPFilter': getattr(net, 'IPFilter', False),
                    'ZeroConfiguration': getattr(net, 'ZeroConfiguration', False),
                    'IPVersion6': getattr(net, 'IPVersion6', False),
                    'DynDNS': getattr(net, 'DynDNS', False),
                    'Dot11Configuration': getattr(net, 'Dot11Configuration', False),
                    'HostnameFromDHCP': getattr(net, 'HostnameFromDHCP', False),
                    'NTP': getattr(net, 'NTP', None),
                    'DHCPv6': getattr(net, 'DHCPv6', False),
                }
                print(f"  [+] Network: IPFilter={svc_caps['Network']['IPFilter']}, "
                      f"ZeroConfig={svc_caps['Network']['ZeroConfiguration']}, "
                      f"IPv6={svc_caps['Network']['IPVersion6']}")

            # Security capabilities
            if hasattr(caps, 'Security') and caps.Security:
                sec = caps.Security
                svc_caps['Security'] = {
                    'TLS1.0': getattr(sec, 'TLS1_0', False),
                    'TLS1.1': getattr(sec, 'TLS1_1', False),
                    'TLS1.2': getattr(sec, 'TLS1_2', False),
                    'OnboardKeyGeneration': getattr(sec, 'OnboardKeyGeneration', False),
                    'AccessPolicyConfig': getattr(sec, 'AccessPolicyConfig', False),
                    'DefaultAccessPolicy': getattr(sec, 'DefaultAccessPolicy', False),
                    'Dot1X': getattr(sec, 'Dot1X', False),
                    'RemoteUserHandling': getattr(sec, 'RemoteUserHandling', False),
                    'X509Token': getattr(sec, 'X_509Token', False),
                    'SAMLToken': getattr(sec, 'SAMLToken', False),
                    'KerberosToken': getattr(sec, 'KerberosToken', False),
                    'UsernameToken': getattr(sec, 'UsernameToken', False),
                    'HttpDigest': getattr(sec, 'HttpDigest', False),
                    'RELToken': getattr(sec, 'RELToken', False),
                    'MaxUsers': getattr(sec, 'MaxUsers', None),
                    'MaxUserNameLength': getattr(sec, 'MaxUserNameLength', None),
                    'MaxPasswordLength': getattr(sec, 'MaxPasswordLength', None),
                }
                print(f"  [+] Security: TLS1.2={svc_caps['Security']['TLS1.2']}, "
                      f"UsernameToken={svc_caps['Security']['UsernameToken']}, "
                      f"MaxUsers={svc_caps['Security']['MaxUsers']}")

            # System capabilities
            if hasattr(caps, 'System') and caps.System:
                sys_cap = caps.System
                svc_caps['System'] = {
                    'DiscoveryResolve': getattr(sys_cap, 'DiscoveryResolve', False),
                    'DiscoveryBye': getattr(sys_cap, 'DiscoveryBye', False),
                    'RemoteDiscovery': getattr(sys_cap, 'RemoteDiscovery', False),
                    'SystemBackup': getattr(sys_cap, 'SystemBackup', False),
                    'SystemLogging': getattr(sys_cap, 'SystemLogging', False),
                    'FirmwareUpgrade': getattr(sys_cap, 'FirmwareUpgrade', False),
                    'HttpFirmwareUpgrade': getattr(sys_cap, 'HttpFirmwareUpgrade', False),
                    'HttpSystemBackup': getattr(sys_cap, 'HttpSystemBackup', False),
                    'HttpSystemLogging': getattr(sys_cap, 'HttpSystemLogging', False),
                    'HttpSupportInformation': getattr(sys_cap, 'HttpSupportInformation', False),
                }
                print(f"  [+] System: Backup={svc_caps['System']['SystemBackup']}, "
                      f"Logging={svc_caps['System']['SystemLogging']}, "
                      f"FirmwareUpgrade={svc_caps['System']['FirmwareUpgrade']}")

            self.results.system['service_capabilities'] = svc_caps
            return svc_caps
        except Exception as e:
            print(f"[-] Failed to get service capabilities: {e}")
            return {}

    def get_scopes(self) -> list:
        """Get device scopes (location, name, etc.)."""
        print("\n[*] Device Scopes")
        print("-" * 50)
        try:
            scopes = self._device_service.GetScopes()
            scope_list = []

            for scope in scopes:
                scope_def = getattr(scope, 'ScopeDef', 'N/A')
                scope_item = getattr(scope, 'ScopeItem', 'N/A')
                scope_list.append({'def': scope_def, 'item': scope_item})

                # Parse common scope patterns
                patterns = [
                    ('onvif.org/name/', 'Name'),
                    ('onvif.org/location/', 'Location'),
                    ('onvif.org/hardware/', 'Hardware'),
                    ('onvif.org/type/', 'Type'),
                    ('onvif.org/Profile/', 'Profile'),
                ]
                printed = False
                for pattern, label in patterns:
                    if pattern in scope_item:
                        value = scope_item.split(pattern)[-1]
                        print(f"  [+] {label}: {value}")
                        printed = True
                        break
                if not printed:
                    print(f"  [+] {scope_item}")

            self.results.scopes = scope_list
            return scope_list
        except Exception as e:
            print(f"[-] Failed to get scopes: {e}")
            return []

    def get_discovery_mode(self) -> dict:
        """Get discovery mode settings."""
        print("\n[*] Discovery Mode")
        print("-" * 50)
        discovery = {}
        try:
            mode = self._device_service.GetDiscoveryMode()
            discovery['mode'] = str(mode)
            print(f"  [+] Discovery Mode: {mode}")
        except Exception as e:
            print(f"[-] Failed to get discovery mode: {e}")

        try:
            remote_mode = self._device_service.GetRemoteDiscoveryMode()
            discovery['remote_mode'] = str(remote_mode)
            print(f"  [+] Remote Discovery Mode: {remote_mode}")
        except Exception as e:
            pass  # Not all devices support this

        try:
            dp_addrs = self._device_service.GetDPAddresses()
            if dp_addrs:
                discovery['dp_addresses'] = [str(addr) for addr in dp_addrs]
                print(f"  [+] DP Addresses: {discovery['dp_addresses']}")
        except Exception:
            pass

        self.results.system['discovery'] = discovery
        return discovery

    def get_endpoint_reference(self) -> str:
        """Get endpoint reference."""
        try:
            epr = self._device_service.GetEndpointReference()
            if epr:
                ref = getattr(epr, 'Address', str(epr))
                self.results.system['endpoint_reference'] = ref
                return ref
        except Exception:
            pass
        return ""

    def get_network_interfaces(self) -> list:
        """Enumerate network interfaces."""
        print("\n[*] Network Interfaces")
        print("-" * 50)
        try:
            interfaces = self._device_service.GetNetworkInterfaces()
            iface_list = []

            for iface in interfaces:
                token = getattr(iface, 'token', 'N/A')
                enabled = getattr(iface, 'Enabled', False)
                info = {'token': token, 'enabled': enabled}

                if hasattr(iface, 'Info') and iface.Info:
                    info['name'] = getattr(iface.Info, 'Name', 'N/A')
                    info['mac'] = getattr(iface.Info, 'HwAddress', 'N/A')
                    info['mtu'] = getattr(iface.Info, 'MTU', 'N/A')
                    print(f"  [+] {info['name']} ({info['mac']}) - Enabled: {enabled}, MTU: {info['mtu']}")

                # IPv4 config
                if hasattr(iface, 'IPv4') and iface.IPv4:
                    info['ipv4'] = {'enabled': getattr(iface.IPv4, 'Enabled', False)}
                    if hasattr(iface.IPv4, 'Config') and iface.IPv4.Config:
                        cfg = iface.IPv4.Config
                        info['ipv4']['dhcp'] = getattr(cfg, 'DHCP', False)
                        if hasattr(cfg, 'Manual') and cfg.Manual:
                            for addr in cfg.Manual:
                                ip = getattr(addr, 'Address', 'N/A')
                                prefix = getattr(addr, 'PrefixLength', 'N/A')
                                info['ipv4']['address'] = f"{ip}/{prefix}"
                                print(f"      IPv4: {ip}/{prefix} (DHCP: {info['ipv4']['dhcp']})")
                        if hasattr(cfg, 'FromDHCP') and cfg.FromDHCP:
                            dhcp_addr = cfg.FromDHCP
                            ip = getattr(dhcp_addr, 'Address', 'N/A')
                            prefix = getattr(dhcp_addr, 'PrefixLength', 'N/A')
                            print(f"      IPv4 (DHCP): {ip}/{prefix}")

                # IPv6 config
                if hasattr(iface, 'IPv6') and iface.IPv6:
                    info['ipv6'] = {'enabled': getattr(iface.IPv6, 'Enabled', False)}
                    if hasattr(iface.IPv6, 'Config') and iface.IPv6.Config:
                        cfg = iface.IPv6.Config
                        info['ipv6']['dhcp'] = getattr(cfg, 'DHCP', None)
                        if hasattr(cfg, 'Manual') and cfg.Manual:
                            for addr in cfg.Manual:
                                ip = getattr(addr, 'Address', 'N/A')
                                prefix = getattr(addr, 'PrefixLength', 'N/A')
                                info['ipv6']['address'] = f"{ip}/{prefix}"
                                print(f"      IPv6: {ip}/{prefix}")

                # Link config
                if hasattr(iface, 'Link') and iface.Link:
                    link = iface.Link
                    if hasattr(link, 'AdminSettings') and link.AdminSettings:
                        info['link_speed'] = getattr(link.AdminSettings, 'Speed', 'N/A')
                        info['duplex'] = getattr(link.AdminSettings, 'Duplex', 'N/A')
                        info['auto_neg'] = getattr(link.AdminSettings, 'AutoNegotiation', False)

                iface_list.append(info)

            self.results.network['interfaces'] = iface_list
            return iface_list
        except Exception as e:
            print(f"[-] Failed to get network interfaces: {e}")
            return []

    def get_network_protocols(self) -> list:
        """Get enabled network protocols."""
        print("\n[*] Network Protocols")
        print("-" * 50)
        try:
            protocols = self._device_service.GetNetworkProtocols()
            proto_list = []

            for proto in protocols:
                name = getattr(proto, 'Name', 'Unknown')
                enabled = getattr(proto, 'Enabled', False)
                ports = []
                if hasattr(proto, 'Port') and proto.Port:
                    ports = [p for p in proto.Port]

                proto_list.append({
                    'name': name,
                    'enabled': enabled,
                    'ports': ports
                })
                port_str = ', '.join(map(str, ports)) if ports else 'N/A'
                status = "Enabled" if enabled else "Disabled"
                print(f"  [+] {name}: {status} (Ports: {port_str})")

            self.results.network['protocols'] = proto_list
            return proto_list
        except Exception as e:
            print(f"[-] Failed to get network protocols: {e}")
            return []

    def get_network_default_gateway(self) -> dict:
        """Get default gateway configuration."""
        try:
            gw = self._device_service.GetNetworkDefaultGateway()
            gateway = {}
            if hasattr(gw, 'IPv4Address') and gw.IPv4Address:
                gateway['ipv4'] = [str(a) for a in gw.IPv4Address]
            if hasattr(gw, 'IPv6Address') and gw.IPv6Address:
                gateway['ipv6'] = [str(a) for a in gw.IPv6Address]
            if gateway:
                self.results.network['gateway'] = gateway
                print(f"  [+] Gateway: {gateway}")
            return gateway
        except Exception:
            return {}

    def get_dns(self) -> dict:
        """Get DNS configuration."""
        print("\n[*] DNS Configuration")
        print("-" * 50)
        dns_info = {}
        try:
            dns = self._device_service.GetDNS()
            dns_info['from_dhcp'] = getattr(dns, 'FromDHCP', False)
            dns_info['search_domain'] = []
            dns_info['servers'] = []

            if hasattr(dns, 'SearchDomain') and dns.SearchDomain:
                dns_info['search_domain'] = list(dns.SearchDomain)
                print(f"  [+] Search Domain: {dns_info['search_domain']}")

            if hasattr(dns, 'DNSManual') and dns.DNSManual:
                for d in dns.DNSManual:
                    if hasattr(d, 'IPv4Address') and d.IPv4Address:
                        dns_info['servers'].append(d.IPv4Address)
                        print(f"  [+] DNS Server: {d.IPv4Address}")
                    if hasattr(d, 'IPv6Address') and d.IPv6Address:
                        dns_info['servers'].append(d.IPv6Address)
                        print(f"  [+] DNS Server (v6): {d.IPv6Address}")

            if hasattr(dns, 'DNSFromDHCP') and dns.DNSFromDHCP:
                for d in dns.DNSFromDHCP:
                    if hasattr(d, 'IPv4Address') and d.IPv4Address:
                        print(f"  [+] DNS Server (DHCP): {d.IPv4Address}")

            self.results.network['dns'] = dns_info
        except Exception as e:
            print(f"[-] Failed to get DNS: {e}")
        return dns_info

    def get_ntp(self) -> dict:
        """Get NTP configuration."""
        print("\n[*] NTP Configuration")
        print("-" * 50)
        ntp_info = {}
        try:
            ntp = self._device_service.GetNTP()
            ntp_info['from_dhcp'] = getattr(ntp, 'FromDHCP', False)
            ntp_info['servers'] = []

            print(f"  [+] NTP From DHCP: {ntp_info['from_dhcp']}")

            if hasattr(ntp, 'NTPManual') and ntp.NTPManual:
                for server in ntp.NTPManual:
                    srv_type = getattr(server, 'Type', 'Unknown')
                    if srv_type == 'IPv4':
                        addr = getattr(server, 'IPv4Address', 'N/A')
                    elif srv_type == 'IPv6':
                        addr = getattr(server, 'IPv6Address', 'N/A')
                    else:
                        addr = getattr(server, 'DNSname', 'N/A')
                    ntp_info['servers'].append({'type': srv_type, 'address': addr})
                    print(f"  [+] NTP Server: {addr} ({srv_type})")

            if hasattr(ntp, 'NTPFromDHCP') and ntp.NTPFromDHCP:
                for server in ntp.NTPFromDHCP:
                    addr = getattr(server, 'IPv4Address', None) or getattr(server, 'DNSname', 'N/A')
                    print(f"  [+] NTP Server (DHCP): {addr}")

            self.results.network['ntp'] = ntp_info
        except Exception as e:
            print(f"[-] Failed to get NTP: {e}")
        return ntp_info

    def get_dynamic_dns(self) -> dict:
        """Get Dynamic DNS configuration."""
        try:
            ddns = self._device_service.GetDynamicDNS()
            ddns_info = {
                'type': getattr(ddns, 'Type', 'N/A'),
                'name': getattr(ddns, 'Name', 'N/A'),
                'ttl': getattr(ddns, 'TTL', 'N/A'),
            }
            if ddns_info['type'] != 'NoUpdate':
                print(f"  [+] Dynamic DNS: {ddns_info['type']} - {ddns_info['name']}")
            self.results.network['dynamic_dns'] = ddns_info
            return ddns_info
        except Exception:
            return {}

    def get_zero_configuration(self) -> dict:
        """Get zero configuration (link-local) settings."""
        try:
            zc = self._device_service.GetZeroConfiguration()
            zc_info = {
                'interface_token': getattr(zc, 'InterfaceToken', 'N/A'),
                'enabled': getattr(zc, 'Enabled', False),
            }
            if hasattr(zc, 'Addresses') and zc.Addresses:
                zc_info['addresses'] = list(zc.Addresses)
            print(f"  [+] Zero Config: Enabled={zc_info['enabled']}")
            self.results.network['zero_config'] = zc_info
            return zc_info
        except Exception:
            return {}

    def get_hostname(self) -> dict:
        """Get hostname configuration."""
        hostname_info = {}
        try:
            hostname = self._device_service.GetHostname()
            hostname_info = {
                'name': getattr(hostname, 'Name', 'N/A'),
                'from_dhcp': getattr(hostname, 'FromDHCP', False),
            }
            print(f"  [+] Hostname: {hostname_info['name']} (DHCP: {hostname_info['from_dhcp']})")
            self.results.system['hostname'] = hostname_info
        except Exception as e:
            print(f"[-] Failed to get hostname: {e}")
        return hostname_info

    def get_system_date_time(self) -> dict:
        """Get system date/time configuration."""
        print("\n[*] System Date/Time")
        print("-" * 50)
        dt_info = {}
        try:
            dt = self._device_service.GetSystemDateAndTime()
            dt_info['type'] = getattr(dt, 'DateTimeType', 'N/A')
            dt_info['daylight_savings'] = getattr(dt, 'DaylightSavings', False)

            if hasattr(dt, 'TimeZone') and dt.TimeZone:
                dt_info['timezone'] = getattr(dt.TimeZone, 'TZ', 'N/A')
                print(f"  [+] Timezone: {dt_info['timezone']}")

            if hasattr(dt, 'UTCDateTime') and dt.UTCDateTime:
                utc = dt.UTCDateTime
                date_str = f"{utc.Date.Year}-{utc.Date.Month:02d}-{utc.Date.Day:02d}"
                time_str = f"{utc.Time.Hour:02d}:{utc.Time.Minute:02d}:{utc.Time.Second:02d}"
                dt_info['utc'] = f"{date_str} {time_str}"
                print(f"  [+] UTC Time: {date_str} {time_str}")

            if hasattr(dt, 'LocalDateTime') and dt.LocalDateTime:
                local = dt.LocalDateTime
                date_str = f"{local.Date.Year}-{local.Date.Month:02d}-{local.Date.Day:02d}"
                time_str = f"{local.Time.Hour:02d}:{local.Time.Minute:02d}:{local.Time.Second:02d}"
                dt_info['local'] = f"{date_str} {time_str}"
                print(f"  [+] Local Time: {date_str} {time_str}")

            print(f"  [+] Time Source: {dt_info['type']}")
            self.results.system['datetime'] = dt_info
        except Exception as e:
            print(f"[-] Failed to get system time: {e}")
        return dt_info

    def get_system_log(self) -> dict:
        """Get system log (if supported)."""
        print("\n[*] System Log")
        print("-" * 50)
        log_info = {}
        try:
            # Try to get system log via HTTP
            log = self._device_service.GetSystemLog({'LogType': 'System'})
            if hasattr(log, 'String') and log.String:
                log_info['system'] = log.String[:2000]  # Truncate for display
                print(f"  [+] System Log ({len(log.String)} chars):")
                # Show last 10 lines
                lines = log.String.strip().split('\n')
                for line in lines[-10:]:
                    print(f"      {line[:100]}")
                if len(lines) > 10:
                    print(f"      ... ({len(lines) - 10} more lines)")
        except Exception as e:
            print(f"[-] System log not available: {e}")

        try:
            log = self._device_service.GetSystemLog({'LogType': 'Access'})
            if hasattr(log, 'String') and log.String:
                log_info['access'] = log.String[:2000]
                print(f"  [+] Access Log ({len(log.String)} chars)")
        except Exception:
            pass

        self.results.system['logs'] = log_info
        return log_info

    def get_system_support_information(self) -> str:
        """Get system support information."""
        try:
            info = self._device_service.GetSystemSupportInformation()
            if hasattr(info, 'String') and info.String:
                self.results.system['support_info'] = info.String[:5000]
                return info.String
        except Exception:
            pass
        return ""

    def get_geo_location(self) -> dict:
        """Get device geo location if available."""
        try:
            loc = self._device_service.GetGeoLocation()
            if loc:
                geo = {}
                for item in loc:
                    if hasattr(item, 'Longitude'):
                        geo['longitude'] = item.Longitude
                    if hasattr(item, 'Latitude'):
                        geo['latitude'] = item.Latitude
                    if hasattr(item, 'Elevation'):
                        geo['elevation'] = item.Elevation
                if geo:
                    print(f"  [+] Geo Location: {geo}")
                    self.results.system['geo_location'] = geo
                return geo
        except Exception:
            pass
        return {}

    def get_system_backup(self) -> dict:
        """Get system configuration backup."""
        print("\n[*] System Backup")
        print("-" * 50)
        backup_info = {}
        try:
            backup = self._device_service.GetSystemBackup()
            if backup:
                backup_info['files'] = []
                for item in backup:
                    file_info = {}
                    if hasattr(item, 'Name'):
                        file_info['name'] = item.Name
                        print(f"  [+] Backup file: {item.Name}")
                    if hasattr(item, 'Data'):
                        data = item.Data
                        if hasattr(data, 'Include'):
                            file_info['include_href'] = data.Include.href if hasattr(data.Include, 'href') else str(data.Include)
                            print(f"      Include: {file_info['include_href']}")
                        elif isinstance(data, bytes):
                            file_info['data_size'] = len(data)
                            file_info['data_preview'] = data[:500].decode('utf-8', errors='replace')
                            print(f"      Data size: {len(data)} bytes")
                            print(f"      Preview: {file_info['data_preview'][:200]}...")
                        elif isinstance(data, str):
                            file_info['data_size'] = len(data)
                            file_info['data'] = data
                            print(f"      Data size: {len(data)} chars")
                            print(f"      Content: {data[:500]}")
                        else:
                            file_info['data_type'] = str(type(data))
                            file_info['data_str'] = str(data)[:1000]
                            print(f"      Data type: {type(data)}")
                            print(f"      Data: {str(data)[:500]}")
                    backup_info['files'].append(file_info)
                self.results.system['backup'] = backup_info
            else:
                print("  [-] No backup data returned")
        except Exception as e:
            print(f"  [-] Backup error: {e}")
        return backup_info

    def restore_system(self, backup_file: str = None) -> bool:
        """Restore system from backup (DANGEROUS - requires confirmation)."""
        print("\n[*] System Restore")
        print("-" * 50)
        print("  [!] WARNING: This operation can modify device configuration!")

        if not backup_file:
            print("  [-] No backup file provided")
            print("  [*] Usage: Pass backup data to restore_system(backup_data)")
            return False

        try:
            # Read backup file if path provided
            if isinstance(backup_file, str) and len(backup_file) < 500:
                import os
                if os.path.exists(backup_file):
                    with open(backup_file, 'rb') as f:
                        backup_data = f.read()
                    print(f"  [*] Loaded backup from: {backup_file}")
                else:
                    backup_data = backup_file.encode() if isinstance(backup_file, str) else backup_file
            else:
                backup_data = backup_file

            # Create backup file structure for ONVIF
            backup_files = [{
                'Name': 'backup.xml',
                'Data': backup_data
            }]

            result = self._device_service.RestoreSystem({'BackupFiles': backup_files})
            print(f"  [+] Restore result: {result}")
            return True
        except Exception as e:
            print(f"  [-] Restore error: {e}")
            return False

    def get_firmware_upgrade_info(self) -> dict:
        """Check if firmware upgrade is supported and get upload URI."""
        print("\n[*] Firmware Upgrade Check")
        print("-" * 50)

        try:
            result = self._device_service.StartFirmwareUpgrade()
            upgrade_info = {
                'supported': True,
                'upload_uri': getattr(result, 'UploadUri', None),
                'upload_delay': str(getattr(result, 'UploadDelay', None)),
                'expected_down_time': str(getattr(result, 'ExpectedDownTime', None)),
            }
            print(f"  [+] Firmware upgrade SUPPORTED!")
            print(f"  [+] Upload URI: {upgrade_info['upload_uri']}")
            print(f"  [+] Upload Delay: {upgrade_info['upload_delay']}")
            print(f"  [+] Expected Downtime: {upgrade_info['expected_down_time']}")
            print(f"  [!] WARNING: Device may be waiting for firmware upload now!")
            return upgrade_info
        except Exception as e:
            err_str = str(e).lower()
            if 'not implemented' in err_str or 'not supported' in err_str:
                print(f"  [-] Firmware upgrade NOT supported")
            elif 'action not supported' in err_str:
                print(f"  [-] Firmware upgrade NOT supported (ActionNotSupported)")
            else:
                print(f"  [-] Firmware upgrade error: {e}")
            return {'supported': False, 'error': str(e)}

    def get_users(self) -> list:
        """Enumerate users (requires admin access)."""
        print("\n[*] Users")
        print("-" * 50)
        try:
            users = self._device_service.GetUsers()
            user_list = []

            for user in users:
                username = getattr(user, 'Username', 'N/A')
                level = getattr(user, 'UserLevel', 'N/A')
                user_list.append({'username': username, 'level': str(level)})
                print(f"  [+] {username} ({level})")

            self.results.users = user_list
            return user_list
        except Exception as e:
            print(f"[-] Failed to enumerate users: {e}")
            return []

    def get_certificates(self) -> list:
        """Get device certificates."""
        print("\n[*] Certificates")
        print("-" * 50)
        cert_list = []
        try:
            certs = self._device_service.GetCertificates()
            for cert in certs:
                cert_id = getattr(cert, 'CertificateID', 'N/A')
                cert_info = {
                    'id': cert_id,
                }
                if hasattr(cert, 'Certificate') and cert.Certificate:
                    # Certificate is typically base64 encoded
                    cert_info['has_certificate'] = True
                    cert_info['certificate_length'] = len(cert.Certificate)
                cert_list.append(cert_info)
                print(f"  [+] Certificate ID: {cert_id}")

            self.results.certificates = cert_list
        except Exception as e:
            print(f"[-] Failed to get certificates: {e}")

        # Get certificate status
        try:
            status = self._device_service.GetCertificatesStatus()
            for s in status:
                cert_id = getattr(s, 'CertificateID', 'N/A')
                enabled = getattr(s, 'Status', False)
                print(f"  [+] Certificate {cert_id} Status: {'Enabled' if enabled else 'Disabled'}")
        except Exception:
            pass

        return cert_list

    def get_access_policy(self) -> dict:
        """Get access policy configuration."""
        try:
            policy = self._device_service.GetAccessPolicy()
            policy_info = {}
            if hasattr(policy, 'User') and policy.User:
                policy_info['users'] = []
                for user in policy.User:
                    username = getattr(user, 'Username', 'N/A')
                    level = getattr(user, 'UserLevel', 'N/A')
                    policy_info['users'].append({'username': username, 'level': str(level)})
            self.results.system['access_policy'] = policy_info
            return policy_info
        except Exception:
            return {}

    def get_ip_address_filter(self) -> dict:
        """Get IP address filter configuration."""
        print("\n[*] IP Address Filter")
        print("-" * 50)
        filter_info = {}
        try:
            ip_filter = self._device_service.GetIPAddressFilter()
            filter_info['type'] = getattr(ip_filter, 'Type', 'N/A')
            filter_info['addresses'] = []

            print(f"  [+] Filter Type: {filter_info['type']}")

            if hasattr(ip_filter, 'IPv4Address') and ip_filter.IPv4Address:
                for addr in ip_filter.IPv4Address:
                    ip = getattr(addr, 'Address', 'N/A')
                    prefix = getattr(addr, 'PrefixLength', 32)
                    filter_info['addresses'].append(f"{ip}/{prefix}")
                    print(f"  [+] IPv4 Filter: {ip}/{prefix}")

            if hasattr(ip_filter, 'IPv6Address') and ip_filter.IPv6Address:
                for addr in ip_filter.IPv6Address:
                    ip = getattr(addr, 'Address', 'N/A')
                    prefix = getattr(addr, 'PrefixLength', 128)
                    filter_info['addresses'].append(f"{ip}/{prefix}")
                    print(f"  [+] IPv6 Filter: {ip}/{prefix}")

            self.results.ip_filter = filter_info
        except Exception as e:
            print(f"[-] IP filter not available: {e}")
        return filter_info

    def get_relay_outputs(self) -> list:
        """Get relay output configuration."""
        print("\n[*] Relay Outputs")
        print("-" * 50)
        relay_list = []
        try:
            relays = self._device_service.GetRelayOutputs()
            for relay in relays:
                token = getattr(relay, 'token', 'N/A')
                relay_info = {'token': token}

                if hasattr(relay, 'Properties') and relay.Properties:
                    props = relay.Properties
                    relay_info['mode'] = getattr(props, 'Mode', 'N/A')
                    relay_info['idle_state'] = getattr(props, 'IdleState', 'N/A')
                    relay_info['delay_time'] = getattr(props, 'DelayTime', 'N/A')

                relay_list.append(relay_info)
                print(f"  [+] Relay: {token} (Mode: {relay_info.get('mode', 'N/A')})")

            self.results.relay_outputs = relay_list
        except Exception as e:
            print(f"[-] Relay outputs not available: {e}")
        return relay_list

    def get_digital_inputs(self) -> list:
        """Get digital input configuration."""
        print("\n[*] Digital Inputs")
        print("-" * 50)
        input_list = []
        try:
            # Try DeviceIO service first
            try:
                deviceio = self.camera.create_deviceio_service()
                inputs = deviceio.GetDigitalInputs()
            except Exception:
                # Fall back to device service
                inputs = self._device_service.GetDigitalInputs()

            for inp in inputs:
                token = getattr(inp, 'token', 'N/A')
                idle_state = getattr(inp, 'IdleState', 'N/A') if hasattr(inp, 'IdleState') else 'N/A'
                input_list.append({
                    'token': token,
                    'idle_state': idle_state
                })
                print(f"  [+] Digital Input: {token} (Idle: {idle_state})")

            self.results.digital_inputs = input_list
        except Exception as e:
            print(f"[-] Digital inputs not available: {e}")
        return input_list

    # =========================================================================
    # MEDIA SERVICE OPERATIONS
    # =========================================================================

    def _get_media_service(self):
        """Get or create media service."""
        if not self._media_service:
            try:
                self._media_service = self.camera.create_media_service()
                self._patch_service_binding(self._media_service)
            except Exception:
                pass
        return self._media_service

    def _get_media2_service(self):
        """Get or create media2 service."""
        if not self._media2_service:
            try:
                self._media2_service = self.camera.create_media2_service()
                self._patch_service_binding(self._media2_service)
            except Exception:
                pass
        return self._media2_service

    def get_profiles(self) -> list:
        """Get media profiles and streaming URIs."""
        print("\n[*] Media Profiles")
        print("-" * 50)
        media_service = self._get_media_service()
        if not media_service:
            print("[-] Media service not available")
            return []

        try:
            profiles = media_service.GetProfiles()
            profile_list = []

            for profile in profiles:
                token = getattr(profile, 'token', 'N/A')
                name = getattr(profile, 'Name', 'N/A')
                fixed = getattr(profile, 'fixed', False)

                profile_info = {
                    'token': token,
                    'name': name,
                    'fixed': fixed,
                    'video_source': None,
                    'video_encoder': None,
                    'audio_source': None,
                    'audio_encoder': None,
                    'ptz': None,
                    'stream_uri': None,
                    'snapshot_uri': None
                }

                print(f"\n  [+] Profile: {name} (token: {token}, fixed: {fixed})")

                # Video source config
                if hasattr(profile, 'VideoSourceConfiguration') and profile.VideoSourceConfiguration:
                    vsc = profile.VideoSourceConfiguration
                    profile_info['video_source'] = {
                        'token': getattr(vsc, 'token', 'N/A'),
                        'name': getattr(vsc, 'Name', 'N/A'),
                        'source_token': getattr(vsc, 'SourceToken', 'N/A'),
                    }
                    if hasattr(vsc, 'Bounds') and vsc.Bounds:
                        b = vsc.Bounds
                        profile_info['video_source']['bounds'] = f"{b.width}x{b.height}+{b.x}+{b.y}"
                        print(f"      Video Source: {profile_info['video_source']['source_token']} "
                              f"({profile_info['video_source']['bounds']})")

                # Video encoder config
                if hasattr(profile, 'VideoEncoderConfiguration') and profile.VideoEncoderConfiguration:
                    vec = profile.VideoEncoderConfiguration
                    encoding = getattr(vec, 'Encoding', 'N/A')
                    resolution = getattr(vec, 'Resolution', None)
                    res_str = f"{resolution.Width}x{resolution.Height}" if resolution else "N/A"
                    quality = getattr(vec, 'Quality', 'N/A')

                    profile_info['video_encoder'] = {
                        'token': getattr(vec, 'token', 'N/A'),
                        'name': getattr(vec, 'Name', 'N/A'),
                        'encoding': str(encoding),
                        'resolution': res_str,
                        'quality': quality,
                    }

                    # Rate control
                    if hasattr(vec, 'RateControl') and vec.RateControl:
                        rc = vec.RateControl
                        profile_info['video_encoder']['framerate'] = getattr(rc, 'FrameRateLimit', 'N/A')
                        profile_info['video_encoder']['bitrate'] = getattr(rc, 'BitrateLimit', 'N/A')
                        profile_info['video_encoder']['encoding_interval'] = getattr(rc, 'EncodingInterval', 'N/A')

                    # H264/H265 config
                    if hasattr(vec, 'H264') and vec.H264:
                        h264 = vec.H264
                        profile_info['video_encoder']['h264_profile'] = getattr(h264, 'H264Profile', 'N/A')
                        profile_info['video_encoder']['gov_length'] = getattr(h264, 'GovLength', 'N/A')
                    elif hasattr(vec, 'MPEG4') and vec.MPEG4:
                        mpeg4 = vec.MPEG4
                        profile_info['video_encoder']['mpeg4_profile'] = getattr(mpeg4, 'Mpeg4Profile', 'N/A')

                    print(f"      Encoding: {encoding} @ {res_str} (Quality: {quality})")
                    if 'framerate' in profile_info['video_encoder']:
                        print(f"      Rate: {profile_info['video_encoder']['framerate']} fps, "
                              f"{profile_info['video_encoder']['bitrate']} kbps")

                # Audio source config
                if hasattr(profile, 'AudioSourceConfiguration') and profile.AudioSourceConfiguration:
                    asc = profile.AudioSourceConfiguration
                    profile_info['audio_source'] = {
                        'token': getattr(asc, 'token', 'N/A'),
                        'name': getattr(asc, 'Name', 'N/A'),
                        'source_token': getattr(asc, 'SourceToken', 'N/A'),
                    }
                    print(f"      Audio Source: {profile_info['audio_source']['source_token']}")

                # Audio encoder config
                if hasattr(profile, 'AudioEncoderConfiguration') and profile.AudioEncoderConfiguration:
                    aec = profile.AudioEncoderConfiguration
                    profile_info['audio_encoder'] = {
                        'token': getattr(aec, 'token', 'N/A'),
                        'name': getattr(aec, 'Name', 'N/A'),
                        'encoding': getattr(aec, 'Encoding', 'N/A'),
                        'bitrate': getattr(aec, 'Bitrate', 'N/A'),
                        'sample_rate': getattr(aec, 'SampleRate', 'N/A'),
                    }
                    print(f"      Audio Encoding: {profile_info['audio_encoder']['encoding']} "
                          f"({profile_info['audio_encoder']['sample_rate']} Hz)")

                # PTZ config
                if hasattr(profile, 'PTZConfiguration') and profile.PTZConfiguration:
                    ptz = profile.PTZConfiguration
                    profile_info['ptz'] = {
                        'token': getattr(ptz, 'token', 'N/A'),
                        'name': getattr(ptz, 'Name', 'N/A'),
                        'node_token': getattr(ptz, 'NodeToken', 'N/A'),
                    }
                    print(f"      PTZ Node: {profile_info['ptz']['node_token']}")

                # Get stream URI
                try:
                    stream_setup = {'Stream': 'RTP-Unicast', 'Transport': {'Protocol': 'RTSP'}}
                    uri_response = media_service.GetStreamUri({
                        'StreamSetup': stream_setup,
                        'ProfileToken': token
                    })
                    stream_uri = getattr(uri_response, 'Uri', None)
                    if stream_uri:
                        profile_info['stream_uri'] = stream_uri
                        print(f"      RTSP URI: {stream_uri}")
                except Exception:
                    pass

                # Get snapshot URI
                try:
                    snap_response = media_service.GetSnapshotUri({'ProfileToken': token})
                    snap_uri = getattr(snap_response, 'Uri', None)
                    if snap_uri:
                        profile_info['snapshot_uri'] = snap_uri
                        print(f"      Snapshot: {snap_uri}")
                except Exception:
                    pass

                profile_list.append(profile_info)

            self.results.profiles = profile_list
            return profile_list
        except Exception as e:
            print(f"[-] Failed to get profiles: {e}")
            return []

    def get_video_sources(self) -> list:
        """Get video sources."""
        print("\n[*] Video Sources")
        print("-" * 50)
        media_service = self._get_media_service()
        if not media_service:
            return []

        source_list = []
        try:
            sources = media_service.GetVideoSources()
            for source in sources:
                token = getattr(source, 'token', 'N/A')
                source_info = {
                    'token': token,
                    'framerate': getattr(source, 'Framerate', 'N/A'),
                }

                if hasattr(source, 'Resolution') and source.Resolution:
                    res = source.Resolution
                    source_info['resolution'] = f"{res.Width}x{res.Height}"

                if hasattr(source, 'Imaging') and source.Imaging:
                    img = source.Imaging
                    source_info['imaging'] = {
                        'brightness': getattr(img, 'Brightness', None),
                        'color_saturation': getattr(img, 'ColorSaturation', None),
                        'contrast': getattr(img, 'Contrast', None),
                        'sharpness': getattr(img, 'Sharpness', None),
                    }

                source_list.append(source_info)
                print(f"  [+] Video Source: {token} ({source_info.get('resolution', 'N/A')} @ "
                      f"{source_info['framerate']} fps)")

            self.results.video_sources = source_list
        except Exception as e:
            print(f"[-] Failed to get video sources: {e}")
        return source_list

    def get_video_source_configurations(self) -> list:
        """Get video source configurations."""
        media_service = self._get_media_service()
        if not media_service:
            return []

        config_list = []
        try:
            configs = media_service.GetVideoSourceConfigurations()
            for cfg in configs:
                token = getattr(cfg, 'token', 'N/A')
                config_info = {
                    'token': token,
                    'name': getattr(cfg, 'Name', 'N/A'),
                    'source_token': getattr(cfg, 'SourceToken', 'N/A'),
                    'use_count': getattr(cfg, 'UseCount', 0),
                }
                if hasattr(cfg, 'Bounds') and cfg.Bounds:
                    b = cfg.Bounds
                    config_info['bounds'] = {'x': b.x, 'y': b.y, 'width': b.width, 'height': b.height}
                config_list.append(config_info)
                print(f"      Video Source Config: {token} -> {config_info['source_token']}")
        except Exception:
            pass
        return config_list

    def get_audio_sources(self) -> list:
        """Get audio sources."""
        print("\n[*] Audio Sources")
        print("-" * 50)
        media_service = self._get_media_service()
        if not media_service:
            return []

        source_list = []
        try:
            sources = media_service.GetAudioSources()
            for source in sources:
                token = getattr(source, 'token', 'N/A')
                channels = getattr(source, 'Channels', 'N/A')
                source_info = {
                    'token': token,
                    'channels': channels,
                }
                source_list.append(source_info)
                print(f"  [+] Audio Source: {token} ({channels} channels)")

            self.results.audio_sources = source_list
        except Exception as e:
            print(f"[-] Audio sources not available: {e}")
        return source_list

    def get_audio_outputs(self) -> list:
        """Get audio outputs."""
        media_service = self._get_media_service()
        if not media_service:
            return []

        output_list = []
        try:
            outputs = media_service.GetAudioOutputs()
            for output in outputs:
                token = getattr(output, 'token', 'N/A')
                output_list.append({'token': token})
                print(f"  [+] Audio Output: {token}")
        except Exception:
            pass
        return output_list

    def get_video_encoder_configurations(self) -> list:
        """Get video encoder configurations."""
        print("\n[*] Video Encoder Configurations")
        print("-" * 50)
        media_service = self._get_media_service()
        if not media_service:
            return []

        encoder_list = []
        try:
            encoders = media_service.GetVideoEncoderConfigurations()
            for enc in encoders:
                token = getattr(enc, 'token', 'N/A')
                name = getattr(enc, 'Name', 'N/A')
                encoding = getattr(enc, 'Encoding', 'N/A')

                enc_info = {
                    'token': token,
                    'name': name,
                    'encoding': str(encoding),
                    'use_count': getattr(enc, 'UseCount', 0),
                    'guaranteed_framerate': getattr(enc, 'GuaranteedFrameRate', False),
                    'quality': getattr(enc, 'Quality', 'N/A'),
                }

                if hasattr(enc, 'Resolution') and enc.Resolution:
                    enc_info['resolution'] = f"{enc.Resolution.Width}x{enc.Resolution.Height}"

                if hasattr(enc, 'RateControl') and enc.RateControl:
                    rc = enc.RateControl
                    enc_info['framerate_limit'] = getattr(rc, 'FrameRateLimit', 'N/A')
                    enc_info['bitrate_limit'] = getattr(rc, 'BitrateLimit', 'N/A')
                    enc_info['encoding_interval'] = getattr(rc, 'EncodingInterval', 'N/A')

                if hasattr(enc, 'H264') and enc.H264:
                    enc_info['h264_profile'] = str(getattr(enc.H264, 'H264Profile', 'N/A'))
                    enc_info['gov_length'] = getattr(enc.H264, 'GovLength', 'N/A')

                if hasattr(enc, 'Multicast') and enc.Multicast:
                    mc = enc.Multicast
                    enc_info['multicast'] = {
                        'port': getattr(mc, 'Port', 'N/A'),
                        'ttl': getattr(mc, 'TTL', 'N/A'),
                        'auto_start': getattr(mc, 'AutoStart', False),
                    }
                    if hasattr(mc, 'Address') and mc.Address:
                        enc_info['multicast']['address'] = getattr(mc.Address, 'IPv4Address', 'N/A')

                encoder_list.append(enc_info)
                print(f"  [+] {name}: {encoding} @ {enc_info.get('resolution', 'N/A')}")
                if 'framerate_limit' in enc_info:
                    print(f"      Rate: {enc_info['framerate_limit']} fps, {enc_info['bitrate_limit']} kbps")

            self.results.video_encoders = encoder_list
        except Exception as e:
            print(f"[-] Failed to get video encoders: {e}")
        return encoder_list

    def get_video_encoder_configuration_options(self, token: str = None) -> dict:
        """Get video encoder configuration options."""
        media_service = self._get_media_service()
        if not media_service:
            return {}

        try:
            params = {}
            if token:
                params['ConfigurationToken'] = token
            options = media_service.GetVideoEncoderConfigurationOptions(params)

            opts = {
                'quality_range': None,
                'h264': None,
                'jpeg': None,
                'mpeg4': None,
            }

            if hasattr(options, 'QualityRange') and options.QualityRange:
                opts['quality_range'] = {
                    'min': options.QualityRange.Min,
                    'max': options.QualityRange.Max
                }

            if hasattr(options, 'H264') and options.H264:
                h264 = options.H264
                opts['h264'] = {
                    'resolutions': [],
                    'gov_length_range': None,
                    'frame_rate_range': None,
                    'encoding_interval_range': None,
                    'profiles': [],
                }
                if hasattr(h264, 'ResolutionsAvailable'):
                    for res in h264.ResolutionsAvailable:
                        opts['h264']['resolutions'].append(f"{res.Width}x{res.Height}")
                if hasattr(h264, 'H264ProfilesSupported'):
                    opts['h264']['profiles'] = [str(p) for p in h264.H264ProfilesSupported]
                if hasattr(h264, 'GovLengthRange'):
                    opts['h264']['gov_length_range'] = {'min': h264.GovLengthRange.Min, 'max': h264.GovLengthRange.Max}
                if hasattr(h264, 'FrameRateRange'):
                    opts['h264']['frame_rate_range'] = {'min': h264.FrameRateRange.Min, 'max': h264.FrameRateRange.Max}

            return opts
        except Exception:
            return {}

    def get_audio_encoder_configurations(self) -> list:
        """Get audio encoder configurations."""
        print("\n[*] Audio Encoder Configurations")
        print("-" * 50)
        media_service = self._get_media_service()
        if not media_service:
            return []

        encoder_list = []
        try:
            encoders = media_service.GetAudioEncoderConfigurations()
            for enc in encoders:
                token = getattr(enc, 'token', 'N/A')
                name = getattr(enc, 'Name', 'N/A')
                encoding = getattr(enc, 'Encoding', 'N/A')

                enc_info = {
                    'token': token,
                    'name': name,
                    'encoding': str(encoding),
                    'bitrate': getattr(enc, 'Bitrate', 'N/A'),
                    'sample_rate': getattr(enc, 'SampleRate', 'N/A'),
                    'use_count': getattr(enc, 'UseCount', 0),
                }

                if hasattr(enc, 'Multicast') and enc.Multicast:
                    mc = enc.Multicast
                    enc_info['multicast'] = {
                        'port': getattr(mc, 'Port', 'N/A'),
                        'ttl': getattr(mc, 'TTL', 'N/A'),
                    }

                encoder_list.append(enc_info)
                print(f"  [+] {name}: {encoding} ({enc_info['sample_rate']} Hz, {enc_info['bitrate']} kbps)")

            self.results.audio_encoders = encoder_list
        except Exception as e:
            print(f"[-] Audio encoders not available: {e}")
        return encoder_list

    def get_osds(self) -> list:
        """Get OSD (On-Screen Display) configurations."""
        print("\n[*] OSD Configurations")
        print("-" * 50)
        media_service = self._get_media_service()
        if not media_service:
            return []

        osd_list = []
        try:
            osds = media_service.GetOSDs({})
            for osd in osds:
                token = getattr(osd, 'token', 'N/A')
                osd_info = {
                    'token': token,
                    'video_source_token': getattr(osd, 'VideoSourceConfigurationToken', 'N/A'),
                    'type': getattr(osd, 'Type', 'N/A'),
                }

                if hasattr(osd, 'Position') and osd.Position:
                    pos = osd.Position
                    osd_info['position'] = {
                        'type': getattr(pos, 'Type', 'N/A'),
                    }
                    if hasattr(pos, 'Pos') and pos.Pos:
                        osd_info['position']['x'] = getattr(pos.Pos, 'x', 0)
                        osd_info['position']['y'] = getattr(pos.Pos, 'y', 0)

                if hasattr(osd, 'TextString') and osd.TextString:
                    ts = osd.TextString
                    osd_info['text'] = {
                        'type': getattr(ts, 'Type', 'N/A'),
                        'plain_text': getattr(ts, 'PlainText', None),
                        'date_format': getattr(ts, 'DateFormat', None),
                        'time_format': getattr(ts, 'TimeFormat', None),
                    }

                osd_list.append(osd_info)
                print(f"  [+] OSD: {token} (Type: {osd_info['type']})")

            self.results.osds = osd_list
        except Exception as e:
            print(f"[-] OSD not available: {e}")
        return osd_list

    def get_metadata_configurations(self) -> list:
        """Get metadata configurations."""
        media_service = self._get_media_service()
        if not media_service:
            return []

        config_list = []
        try:
            configs = media_service.GetMetadataConfigurations()
            for cfg in configs:
                token = getattr(cfg, 'token', 'N/A')
                config_info = {
                    'token': token,
                    'name': getattr(cfg, 'Name', 'N/A'),
                    'use_count': getattr(cfg, 'UseCount', 0),
                    'analytics': getattr(cfg, 'Analytics', False),
                }
                if hasattr(cfg, 'PTZStatus') and cfg.PTZStatus:
                    config_info['ptz_status'] = {
                        'status': getattr(cfg.PTZStatus, 'Status', False),
                        'position': getattr(cfg.PTZStatus, 'Position', False),
                    }
                config_list.append(config_info)
                print(f"      Metadata Config: {token} (Analytics: {config_info['analytics']})")
        except Exception:
            pass
        return config_list

    # =========================================================================
    # PTZ SERVICE OPERATIONS
    # =========================================================================

    def _get_ptz_service(self):
        """Get or create PTZ service."""
        if not self._ptz_service:
            try:
                self._ptz_service = self.camera.create_ptz_service()
                self._patch_service_binding(self._ptz_service)
            except Exception:
                pass
        return self._ptz_service

    def get_ptz_capabilities(self) -> dict:
        """Enumerate PTZ capabilities if available."""
        print("\n[*] PTZ Capabilities")
        print("-" * 50)
        ptz_service = self._get_ptz_service()
        if not ptz_service:
            print("[-] PTZ service not available")
            return {}

        ptz_info = {'configurations': [], 'nodes': [], 'presets': []}

        try:
            # Get PTZ configurations
            configs = ptz_service.GetConfigurations()

            for config in configs:
                token = getattr(config, 'token', 'N/A')
                name = getattr(config, 'Name', 'N/A')
                node_token = getattr(config, 'NodeToken', 'N/A')

                config_info = {
                    'token': token,
                    'name': name,
                    'node_token': node_token,
                    'move_ramp': getattr(config, 'MoveRamp', None),
                    'preset_ramp': getattr(config, 'PresetRamp', None),
                    'preset_tour_ramp': getattr(config, 'PresetTourRamp', None),
                }

                # Default speeds
                if hasattr(config, 'DefaultPTZSpeed') and config.DefaultPTZSpeed:
                    speed = config.DefaultPTZSpeed
                    config_info['default_speed'] = {}
                    if hasattr(speed, 'PanTilt') and speed.PanTilt:
                        config_info['default_speed']['pan_tilt'] = {
                            'x': speed.PanTilt.x,
                            'y': speed.PanTilt.y
                        }
                    if hasattr(speed, 'Zoom') and speed.Zoom:
                        config_info['default_speed']['zoom'] = speed.Zoom.x

                # Timeouts
                if hasattr(config, 'DefaultPTZTimeout'):
                    config_info['default_timeout'] = str(config.DefaultPTZTimeout)

                # Limits
                if hasattr(config, 'PanTiltLimits') and config.PanTiltLimits:
                    limits = config.PanTiltLimits
                    if hasattr(limits, 'Range') and limits.Range:
                        r = limits.Range
                        config_info['pan_tilt_limits'] = {
                            'uri': getattr(r, 'URI', 'N/A'),
                            'x_range': {'min': r.XRange.Min, 'max': r.XRange.Max} if hasattr(r, 'XRange') else None,
                            'y_range': {'min': r.YRange.Min, 'max': r.YRange.Max} if hasattr(r, 'YRange') else None,
                        }

                if hasattr(config, 'ZoomLimits') and config.ZoomLimits:
                    limits = config.ZoomLimits
                    if hasattr(limits, 'Range') and limits.Range:
                        r = limits.Range
                        config_info['zoom_limits'] = {
                            'uri': getattr(r, 'URI', 'N/A'),
                            'x_range': {'min': r.XRange.Min, 'max': r.XRange.Max} if hasattr(r, 'XRange') else None,
                        }

                ptz_info['configurations'].append(config_info)
                print(f"  [+] Configuration: {name} (token: {token})")

                # Get PTZ node for this config
                try:
                    node = ptz_service.GetNode({'NodeToken': node_token})
                    node_info = {
                        'token': node_token,
                        'name': getattr(node, 'Name', 'N/A'),
                        'home_supported': getattr(node, 'HomeSupported', False),
                        'fixed_home': getattr(node, 'FixedHomePosition', False),
                        'geo_move': getattr(node, 'GeoMove', False),
                        'max_presets': getattr(node, 'MaximumNumberOfPresets', 0),
                        'supported_spaces': [],
                        'aux_commands': [],
                    }

                    # Parse supported spaces
                    if hasattr(node, 'SupportedPTZSpaces') and node.SupportedPTZSpaces:
                        spaces = node.SupportedPTZSpaces
                        space_types = [
                            ('AbsolutePanTiltPositionSpace', 'AbsolutePanTilt'),
                            ('AbsoluteZoomPositionSpace', 'AbsoluteZoom'),
                            ('RelativePanTiltTranslationSpace', 'RelativePanTilt'),
                            ('RelativeZoomTranslationSpace', 'RelativeZoom'),
                            ('ContinuousPanTiltVelocitySpace', 'ContinuousPanTilt'),
                            ('ContinuousZoomVelocitySpace', 'ContinuousZoom'),
                            ('PanTiltSpeedSpace', 'PanTiltSpeed'),
                            ('ZoomSpeedSpace', 'ZoomSpeed'),
                        ]
                        for attr, name in space_types:
                            if hasattr(spaces, attr) and getattr(spaces, attr):
                                node_info['supported_spaces'].append(name)

                    if node_info['supported_spaces']:
                        print(f"      Supported: {', '.join(node_info['supported_spaces'])}")

                    if node_info['home_supported']:
                        print(f"      Home Position: Supported (Fixed: {node_info['fixed_home']})")

                    print(f"      Max Presets: {node_info['max_presets']}")

                    # Auxiliary commands
                    if hasattr(node, 'AuxiliaryCommands') and node.AuxiliaryCommands:
                        node_info['aux_commands'] = list(node.AuxiliaryCommands)
                        print(f"      Aux Commands: {node_info['aux_commands']}")

                    ptz_info['nodes'].append(node_info)
                except Exception:
                    pass

            # Get presets for first profile
            media_service = self._get_media_service()
            if media_service:
                try:
                    profiles = media_service.GetProfiles()
                    if profiles:
                        presets = ptz_service.GetPresets({'ProfileToken': profiles[0].token})
                        if presets:
                            print(f"\n  [+] Presets ({len(presets)} found):")
                            for preset in presets[:15]:
                                p_token = getattr(preset, 'token', 'N/A')
                                p_name = getattr(preset, 'Name', 'N/A')
                                preset_info = {'token': p_token, 'name': p_name}

                                if hasattr(preset, 'PTZPosition') and preset.PTZPosition:
                                    pos = preset.PTZPosition
                                    if hasattr(pos, 'PanTilt') and pos.PanTilt:
                                        preset_info['pan'] = pos.PanTilt.x
                                        preset_info['tilt'] = pos.PanTilt.y
                                    if hasattr(pos, 'Zoom') and pos.Zoom:
                                        preset_info['zoom'] = pos.Zoom.x

                                ptz_info['presets'].append(preset_info)
                                print(f"      - {p_name} (token: {p_token})")
                            if len(presets) > 15:
                                print(f"      ... and {len(presets) - 15} more")
                except Exception:
                    pass

            # Get preset tours
            try:
                if profiles:
                    tours = ptz_service.GetPresetTours({'ProfileToken': profiles[0].token})
                    if tours:
                        ptz_info['preset_tours'] = []
                        print(f"\n  [+] Preset Tours ({len(tours)} found):")
                        for tour in tours:
                            tour_token = getattr(tour, 'token', 'N/A')
                            tour_name = getattr(tour, 'Name', 'N/A')
                            tour_info = {'token': tour_token, 'name': tour_name}
                            if hasattr(tour, 'Status') and tour.Status:
                                tour_info['state'] = getattr(tour.Status, 'State', 'N/A')
                            ptz_info['preset_tours'].append(tour_info)
                            print(f"      - {tour_name} (token: {tour_token})")
            except Exception:
                pass

            self.results.ptz = ptz_info
            return ptz_info
        except socket.timeout:
            print("[-] PTZ error: Connection timed out (service URL may be unreachable)")
            return {}
        except Exception as e:
            if 'timed out' in str(e).lower() or 'timeout' in str(e).lower():
                print("[-] PTZ error: Connection timed out (service URL may be unreachable)")
            else:
                print(f"[-] PTZ error: {e}")
            return {}

    def get_ptz_status(self, profile_token: str = None) -> dict:
        """Get current PTZ status."""
        ptz_service = self._get_ptz_service()
        if not ptz_service:
            return {}

        try:
            if not profile_token:
                media_service = self._get_media_service()
                if media_service:
                    profiles = media_service.GetProfiles()
                    if profiles:
                        profile_token = profiles[0].token

            if profile_token:
                status = ptz_service.GetStatus({'ProfileToken': profile_token})
                status_info = {}

                if hasattr(status, 'Position') and status.Position:
                    pos = status.Position
                    status_info['position'] = {}
                    if hasattr(pos, 'PanTilt') and pos.PanTilt:
                        status_info['position']['pan'] = pos.PanTilt.x
                        status_info['position']['tilt'] = pos.PanTilt.y
                    if hasattr(pos, 'Zoom') and pos.Zoom:
                        status_info['position']['zoom'] = pos.Zoom.x

                if hasattr(status, 'MoveStatus') and status.MoveStatus:
                    ms = status.MoveStatus
                    status_info['move_status'] = {
                        'pan_tilt': str(getattr(ms, 'PanTilt', 'N/A')),
                        'zoom': str(getattr(ms, 'Zoom', 'N/A')),
                    }

                if hasattr(status, 'Error'):
                    status_info['error'] = status.Error

                print(f"      PTZ Status: {status_info}")
                return status_info
        except Exception:
            pass
        return {}

    # =========================================================================
    # IMAGING SERVICE OPERATIONS
    # =========================================================================

    def _get_imaging_service(self):
        """Get or create imaging service."""
        if not self._imaging_service:
            try:
                self._imaging_service = self.camera.create_imaging_service()
                self._patch_service_binding(self._imaging_service)
            except Exception:
                pass
        return self._imaging_service

    def get_imaging_settings(self) -> dict:
        """Get imaging settings for video sources."""
        print("\n[*] Imaging Settings")
        print("-" * 50)
        imaging_service = self._get_imaging_service()
        if not imaging_service:
            print("[-] Imaging service not available")
            return {}

        imaging_info = {'sources': []}

        # Get video sources first
        media_service = self._get_media_service()
        if not media_service:
            return imaging_info

        try:
            sources = media_service.GetVideoSources()
            for source in sources:
                token = source.token
                source_imaging = {'token': token}

                try:
                    settings = imaging_service.GetImagingSettings({'VideoSourceToken': token})

                    source_imaging['settings'] = {
                        'brightness': getattr(settings, 'Brightness', None),
                        'color_saturation': getattr(settings, 'ColorSaturation', None),
                        'contrast': getattr(settings, 'Contrast', None),
                        'sharpness': getattr(settings, 'Sharpness', None),
                        'ir_cut_filter': str(getattr(settings, 'IrCutFilter', 'N/A')),
                    }

                    # Backlight compensation
                    if hasattr(settings, 'BacklightCompensation') and settings.BacklightCompensation:
                        blc = settings.BacklightCompensation
                        source_imaging['settings']['backlight_compensation'] = {
                            'mode': str(getattr(blc, 'Mode', 'N/A')),
                            'level': getattr(blc, 'Level', None),
                        }

                    # Exposure
                    if hasattr(settings, 'Exposure') and settings.Exposure:
                        exp = settings.Exposure
                        source_imaging['settings']['exposure'] = {
                            'mode': str(getattr(exp, 'Mode', 'N/A')),
                            'priority': str(getattr(exp, 'Priority', 'N/A')),
                            'min_exposure_time': getattr(exp, 'MinExposureTime', None),
                            'max_exposure_time': getattr(exp, 'MaxExposureTime', None),
                            'min_gain': getattr(exp, 'MinGain', None),
                            'max_gain': getattr(exp, 'MaxGain', None),
                            'min_iris': getattr(exp, 'MinIris', None),
                            'max_iris': getattr(exp, 'MaxIris', None),
                            'exposure_time': getattr(exp, 'ExposureTime', None),
                            'gain': getattr(exp, 'Gain', None),
                            'iris': getattr(exp, 'Iris', None),
                        }

                    # Focus
                    if hasattr(settings, 'Focus') and settings.Focus:
                        foc = settings.Focus
                        source_imaging['settings']['focus'] = {
                            'auto_focus_mode': str(getattr(foc, 'AutoFocusMode', 'N/A')),
                            'default_speed': getattr(foc, 'DefaultSpeed', None),
                            'near_limit': getattr(foc, 'NearLimit', None),
                            'far_limit': getattr(foc, 'FarLimit', None),
                        }

                    # White balance
                    if hasattr(settings, 'WhiteBalance') and settings.WhiteBalance:
                        wb = settings.WhiteBalance
                        source_imaging['settings']['white_balance'] = {
                            'mode': str(getattr(wb, 'Mode', 'N/A')),
                            'cr_gain': getattr(wb, 'CrGain', None),
                            'cb_gain': getattr(wb, 'CbGain', None),
                        }

                    # Wide dynamic range
                    if hasattr(settings, 'WideDynamicRange') and settings.WideDynamicRange:
                        wdr = settings.WideDynamicRange
                        source_imaging['settings']['wide_dynamic_range'] = {
                            'mode': str(getattr(wdr, 'Mode', 'N/A')),
                            'level': getattr(wdr, 'Level', None),
                        }

                    print(f"  [+] Video Source: {token}")
                    print(f"      Brightness: {source_imaging['settings']['brightness']}, "
                          f"Contrast: {source_imaging['settings']['contrast']}, "
                          f"Saturation: {source_imaging['settings']['color_saturation']}")
                    print(f"      IR Cut Filter: {source_imaging['settings']['ir_cut_filter']}")

                except Exception as e:
                    print(f"  [-] Failed to get settings for {token}: {e}")

                # Get imaging options
                try:
                    options = imaging_service.GetOptions({'VideoSourceToken': token})
                    source_imaging['options'] = {}

                    if hasattr(options, 'Brightness') and options.Brightness:
                        source_imaging['options']['brightness_range'] = {
                            'min': options.Brightness.Min,
                            'max': options.Brightness.Max
                        }
                    if hasattr(options, 'Contrast') and options.Contrast:
                        source_imaging['options']['contrast_range'] = {
                            'min': options.Contrast.Min,
                            'max': options.Contrast.Max
                        }
                    if hasattr(options, 'Sharpness') and options.Sharpness:
                        source_imaging['options']['sharpness_range'] = {
                            'min': options.Sharpness.Min,
                            'max': options.Sharpness.Max
                        }
                    if hasattr(options, 'IrCutFilterModes') and options.IrCutFilterModes:
                        source_imaging['options']['ir_cut_modes'] = [str(m) for m in options.IrCutFilterModes]

                except Exception:
                    pass

                # Get imaging status
                try:
                    status = imaging_service.GetStatus({'VideoSourceToken': token})
                    source_imaging['status'] = {}
                    if hasattr(status, 'FocusStatus20') and status.FocusStatus20:
                        fs = status.FocusStatus20
                        source_imaging['status']['focus'] = {
                            'position': getattr(fs, 'Position', None),
                            'move_status': str(getattr(fs, 'MoveStatus', 'N/A')),
                            'error': getattr(fs, 'Error', None),
                        }
                except Exception:
                    pass

                imaging_info['sources'].append(source_imaging)

            self.results.imaging = imaging_info
        except Exception as e:
            print(f"[-] Imaging error: {e}")

        return imaging_info

    def get_imaging_move_options(self, video_source_token: str) -> dict:
        """Get imaging move options (for focus control)."""
        imaging_service = self._get_imaging_service()
        if not imaging_service:
            return {}

        try:
            options = imaging_service.GetMoveOptions({'VideoSourceToken': video_source_token})
            move_opts = {}

            if hasattr(options, 'Absolute') and options.Absolute:
                abs_opt = options.Absolute
                move_opts['absolute'] = {
                    'position_range': {'min': abs_opt.Position.Min, 'max': abs_opt.Position.Max} if hasattr(abs_opt, 'Position') else None,
                    'speed_range': {'min': abs_opt.Speed.Min, 'max': abs_opt.Speed.Max} if hasattr(abs_opt, 'Speed') else None,
                }

            if hasattr(options, 'Relative') and options.Relative:
                rel_opt = options.Relative
                move_opts['relative'] = {
                    'distance_range': {'min': rel_opt.Distance.Min, 'max': rel_opt.Distance.Max} if hasattr(rel_opt, 'Distance') else None,
                    'speed_range': {'min': rel_opt.Speed.Min, 'max': rel_opt.Speed.Max} if hasattr(rel_opt, 'Speed') else None,
                }

            if hasattr(options, 'Continuous') and options.Continuous:
                cont_opt = options.Continuous
                move_opts['continuous'] = {
                    'speed_range': {'min': cont_opt.Speed.Min, 'max': cont_opt.Speed.Max} if hasattr(cont_opt, 'Speed') else None,
                }

            return move_opts
        except Exception:
            return {}

    # =========================================================================
    # EVENTS SERVICE OPERATIONS
    # =========================================================================

    def _get_events_service(self):
        """Get or create events service."""
        if not self._events_service:
            try:
                self._events_service = self.camera.create_events_service()
                self._patch_service_binding(self._events_service)
            except Exception:
                pass
        return self._events_service

    def get_event_properties(self) -> dict:
        """Get event service properties and supported topics."""
        print("\n[*] Event Properties")
        print("-" * 50)
        events_service = self._get_events_service()
        if not events_service:
            print("[-] Events service not available")
            return {}

        event_info = {}

        try:
            props = events_service.GetEventProperties()

            # Topic namespace
            if hasattr(props, 'TopicNamespaceLocation') and props.TopicNamespaceLocation:
                event_info['topic_namespace_locations'] = list(props.TopicNamespaceLocation)

            # Fixed topic set
            event_info['fixed_topic_set'] = getattr(props, 'FixedTopicSet', False)

            # Topic set
            if hasattr(props, 'TopicSet') and props.TopicSet:
                event_info['topics'] = []
                # Parse topic set - this can be complex nested XML
                topic_set = props.TopicSet
                # Try to extract topic names
                if hasattr(topic_set, '_value_1'):
                    for topic in topic_set._value_1:
                        topic_name = getattr(topic, 'Name', None) or str(topic)
                        event_info['topics'].append(topic_name)

            # Message content filter dialects
            if hasattr(props, 'MessageContentFilterDialect') and props.MessageContentFilterDialect:
                event_info['content_filter_dialects'] = list(props.MessageContentFilterDialect)

            # Message content schema locations
            if hasattr(props, 'MessageContentSchemaLocation') and props.MessageContentSchemaLocation:
                event_info['content_schema_locations'] = list(props.MessageContentSchemaLocation)

            # Topic expression dialects
            if hasattr(props, 'TopicExpressionDialect') and props.TopicExpressionDialect:
                event_info['topic_expression_dialects'] = list(props.TopicExpressionDialect)

            print(f"  [+] Fixed Topic Set: {event_info['fixed_topic_set']}")
            if 'topics' in event_info and event_info['topics']:
                print(f"  [+] Topics ({len(event_info['topics'])} found)")
                for topic in event_info['topics'][:10]:
                    print(f"      - {topic}")
                if len(event_info['topics']) > 10:
                    print(f"      ... and {len(event_info['topics']) - 10} more")

            self.results.events = event_info
        except Exception as e:
            print(f"[-] Failed to get event properties: {e}")

        return event_info

    def get_event_service_capabilities(self) -> dict:
        """Get event service capabilities."""
        events_service = self._get_events_service()
        if not events_service:
            return {}

        try:
            caps = events_service.GetServiceCapabilities()
            event_caps = {
                'ws_subscription_policy_support': getattr(caps, 'WSSubscriptionPolicySupport', False),
                'ws_pull_point_support': getattr(caps, 'WSPullPointSupport', False),
                'ws_pausable_subscription_manager': getattr(caps, 'WSPausableSubscriptionManagerInterfaceSupport', False),
                'max_notification_producers': getattr(caps, 'MaxNotificationProducers', None),
                'max_pull_points': getattr(caps, 'MaxPullPoints', None),
                'persistent_notification_storage': getattr(caps, 'PersistentNotificationStorage', False),
            }
            print(f"  [+] Event Capabilities: PullPoint={event_caps['ws_pull_point_support']}, "
                  f"MaxPullPoints={event_caps['max_pull_points']}")
            return event_caps
        except Exception:
            return {}

    def create_pull_point_subscription(self) -> dict:
        """Create a pull point subscription for events."""
        events_service = self._get_events_service()
        if not events_service:
            return {}

        try:
            subscription = events_service.CreatePullPointSubscription({})
            sub_info = {}

            if hasattr(subscription, 'SubscriptionReference') and subscription.SubscriptionReference:
                ref = subscription.SubscriptionReference
                sub_info['address'] = getattr(ref, 'Address', None)
                if hasattr(sub_info['address'], '_value_1'):
                    sub_info['address'] = sub_info['address']._value_1

            if hasattr(subscription, 'CurrentTime'):
                sub_info['current_time'] = str(subscription.CurrentTime)

            if hasattr(subscription, 'TerminationTime'):
                sub_info['termination_time'] = str(subscription.TerminationTime)

            print(f"  [+] Pull Point Subscription created: {sub_info.get('address', 'N/A')}")
            return sub_info
        except Exception as e:
            print(f"[-] Failed to create pull point: {e}")
            return {}

    # =========================================================================
    # ANALYTICS SERVICE OPERATIONS
    # =========================================================================

    def _get_analytics_service(self):
        """Get or create analytics service."""
        if not self._analytics_service:
            try:
                self._analytics_service = self.camera.create_analytics_service()
                self._patch_service_binding(self._analytics_service)
            except Exception:
                pass
        return self._analytics_service

    def get_analytics_capabilities(self) -> dict:
        """Get analytics service capabilities and modules."""
        print("\n[*] Analytics Capabilities")
        print("-" * 50)
        analytics_service = self._get_analytics_service()
        if not analytics_service:
            print("[-] Analytics service not available")
            return {}

        analytics_info = {'modules': [], 'rules': []}

        # Get supported analytics modules
        try:
            # First get video analytics configurations from profiles
            media_service = self._get_media_service()
            if media_service:
                profiles = media_service.GetProfiles()
                for profile in profiles:
                    if hasattr(profile, 'VideoAnalyticsConfiguration') and profile.VideoAnalyticsConfiguration:
                        vac = profile.VideoAnalyticsConfiguration
                        config_token = vac.token

                        # Get supported modules
                        try:
                            modules = analytics_service.GetSupportedAnalyticsModules({
                                'ConfigurationToken': config_token
                            })
                            if hasattr(modules, 'SupportedAnalyticsModule'):
                                for mod in modules.SupportedAnalyticsModule:
                                    mod_info = {
                                        'name': getattr(mod, 'Name', 'N/A'),
                                        'type': str(getattr(mod, 'Type', 'N/A')),
                                    }
                                    analytics_info['modules'].append(mod_info)
                                    print(f"  [+] Module: {mod_info['name']} ({mod_info['type']})")
                        except Exception:
                            pass

                        # Get supported rules
                        try:
                            rules = analytics_service.GetSupportedRules({
                                'ConfigurationToken': config_token
                            })
                            if hasattr(rules, 'SupportedRules'):
                                for rule in rules.SupportedRules:
                                    rule_info = {
                                        'name': getattr(rule, 'Name', 'N/A'),
                                        'type': str(getattr(rule, 'Type', 'N/A')),
                                    }
                                    analytics_info['rules'].append(rule_info)
                                    print(f"  [+] Rule: {rule_info['name']} ({rule_info['type']})")
                        except Exception:
                            pass

                        # Get active rules
                        try:
                            active_rules = analytics_service.GetRules({
                                'ConfigurationToken': config_token
                            })
                            if active_rules:
                                analytics_info['active_rules'] = []
                                print(f"\n  [+] Active Rules:")
                                for rule in active_rules:
                                    rule_name = getattr(rule, 'Name', 'N/A')
                                    rule_type = str(getattr(rule, 'Type', 'N/A'))
                                    analytics_info['active_rules'].append({
                                        'name': rule_name,
                                        'type': rule_type
                                    })
                                    print(f"      - {rule_name} ({rule_type})")
                        except Exception:
                            pass

                        # Get active modules
                        try:
                            active_modules = analytics_service.GetAnalyticsModules({
                                'ConfigurationToken': config_token
                            })
                            if active_modules:
                                analytics_info['active_modules'] = []
                                print(f"\n  [+] Active Modules:")
                                for mod in active_modules:
                                    mod_name = getattr(mod, 'Name', 'N/A')
                                    mod_type = str(getattr(mod, 'Type', 'N/A'))
                                    analytics_info['active_modules'].append({
                                        'name': mod_name,
                                        'type': mod_type
                                    })
                                    print(f"      - {mod_name} ({mod_type})")
                        except Exception:
                            pass

                        break  # Only process first profile with analytics

            self.results.analytics = analytics_info
        except Exception as e:
            print(f"[-] Analytics error: {e}")

        return analytics_info

    # =========================================================================
    # RECORDING SERVICE OPERATIONS
    # =========================================================================

    def _get_recording_service(self):
        """Get or create recording service."""
        if not self._recording_service:
            try:
                self._recording_service = self.camera.create_recording_service()
                self._patch_service_binding(self._recording_service)
            except Exception:
                pass
        return self._recording_service

    def get_recordings(self) -> dict:
        """Get recording information."""
        print("\n[*] Recordings")
        print("-" * 50)
        recording_service = self._get_recording_service()
        if not recording_service:
            print("[-] Recording service not available")
            return {}

        recording_info = {'recordings': [], 'jobs': []}

        # Get recordings
        try:
            recordings = recording_service.GetRecordings()
            for rec in recordings:
                token = getattr(rec, 'RecordingToken', 'N/A')
                rec_info = {'token': token}

                if hasattr(rec, 'Configuration') and rec.Configuration:
                    cfg = rec.Configuration
                    rec_info['config'] = {
                        'max_retention_time': str(getattr(cfg, 'MaximumRetentionTime', 'N/A')),
                    }
                    if hasattr(cfg, 'Source') and cfg.Source:
                        src = cfg.Source
                        rec_info['config']['source'] = {
                            'source_id': getattr(src, 'SourceId', 'N/A'),
                            'name': getattr(src, 'Name', 'N/A'),
                            'location': getattr(src, 'Location', 'N/A'),
                            'address': getattr(src, 'Address', 'N/A'),
                        }
                    if hasattr(cfg, 'Content'):
                        rec_info['config']['content'] = cfg.Content

                if hasattr(rec, 'Tracks') and rec.Tracks:
                    rec_info['tracks'] = []
                    if hasattr(rec.Tracks, 'Track'):
                        for track in rec.Tracks.Track:
                            track_info = {
                                'token': getattr(track, 'TrackToken', 'N/A'),
                            }
                            if hasattr(track, 'Configuration') and track.Configuration:
                                track_info['type'] = str(getattr(track.Configuration, 'TrackType', 'N/A'))
                                track_info['description'] = getattr(track.Configuration, 'Description', 'N/A')
                            rec_info['tracks'].append(track_info)

                recording_info['recordings'].append(rec_info)
                print(f"  [+] Recording: {token}")
                if 'tracks' in rec_info:
                    for track in rec_info['tracks']:
                        print(f"      Track: {track['token']} ({track.get('type', 'N/A')})")

        except Exception as e:
            print(f"[-] Failed to get recordings: {e}")

        # Get recording jobs
        try:
            jobs = recording_service.GetRecordingJobs()
            for job in jobs:
                token = getattr(job, 'JobToken', 'N/A')
                job_info = {'token': token}

                if hasattr(job, 'JobConfiguration') and job.JobConfiguration:
                    cfg = job.JobConfiguration
                    job_info['recording_token'] = getattr(cfg, 'RecordingToken', 'N/A')
                    job_info['mode'] = str(getattr(cfg, 'Mode', 'N/A'))
                    job_info['priority'] = getattr(cfg, 'Priority', 'N/A')

                recording_info['jobs'].append(job_info)
                print(f"  [+] Recording Job: {token} (Mode: {job_info.get('mode', 'N/A')})")

        except Exception:
            pass

        # Get recording options
        try:
            options = recording_service.GetRecordingOptions({'RecordingToken': recording_info['recordings'][0]['token']})
            recording_info['options'] = {
                'spare_jobs': getattr(options.Job, 'Spare', 0) if hasattr(options, 'Job') else None,
                'spare_tracks': getattr(options.Track, 'SpareTotal', 0) if hasattr(options, 'Track') else None,
            }
        except Exception:
            pass

        self.results.recording = recording_info
        return recording_info

    def get_recording_configuration(self, recording_token: str) -> dict:
        """Get configuration for a specific recording."""
        recording_service = self._get_recording_service()
        if not recording_service:
            return {}

        try:
            config = recording_service.GetRecordingConfiguration({'RecordingToken': recording_token})
            return {
                'max_retention_time': str(getattr(config, 'MaximumRetentionTime', 'N/A')),
            }
        except Exception:
            return {}

    # =========================================================================
    # SEARCH SERVICE OPERATIONS
    # =========================================================================

    def _get_search_service(self):
        """Get or create search service."""
        if not self._search_service:
            try:
                self._search_service = self.camera.create_search_service()
                self._patch_service_binding(self._search_service)
            except Exception:
                pass
        return self._search_service

    def get_recording_search_results(self) -> dict:
        """Search for recordings."""
        print("\n[*] Recording Search")
        print("-" * 50)
        search_service = self._get_search_service()
        if not search_service:
            print("[-] Search service not available")
            return {}

        search_info = {}

        try:
            # Get search capabilities
            caps = search_service.GetServiceCapabilities()
            search_info['capabilities'] = {
                'metadata_search': getattr(caps, 'MetadataSearch', False),
                'general_start_events': getattr(caps, 'GeneralStartEvents', False),
            }
            print(f"  [+] Search Capabilities: MetadataSearch={search_info['capabilities']['metadata_search']}")

            # Find recordings
            search_scope = {}  # Empty scope searches all
            search_request = search_service.FindRecordings({
                'Scope': search_scope,
                'MaxMatches': 100,
                'KeepAliveTime': 'PT60S'
            })

            search_token = getattr(search_request, 'SearchToken', None)
            if search_token:
                search_info['search_token'] = search_token

                # Get results
                results = search_service.GetRecordingSearchResults({
                    'SearchToken': search_token,
                    'MinResults': 1,
                    'MaxResults': 50,
                    'WaitTime': 'PT5S'
                })

                if hasattr(results, 'ResultList') and results.ResultList:
                    search_info['recordings'] = []
                    if hasattr(results.ResultList, 'RecordingInformation'):
                        for rec in results.ResultList.RecordingInformation:
                            rec_info = {
                                'token': getattr(rec, 'RecordingToken', 'N/A'),
                            }
                            if hasattr(rec, 'EarliestRecording'):
                                rec_info['earliest'] = str(rec.EarliestRecording)
                            if hasattr(rec, 'LatestRecording'):
                                rec_info['latest'] = str(rec.LatestRecording)
                            if hasattr(rec, 'Content'):
                                rec_info['content'] = rec.Content
                            if hasattr(rec, 'RecordingStatus'):
                                rec_info['status'] = str(rec.RecordingStatus)
                            search_info['recordings'].append(rec_info)
                            print(f"  [+] Found: {rec_info['token']}")
                            if 'earliest' in rec_info:
                                print(f"      Time Range: {rec_info['earliest']} - {rec_info.get('latest', 'N/A')}")

                # End search
                try:
                    search_service.EndSearch({'SearchToken': search_token})
                except Exception:
                    pass

            self.results.search = search_info
        except Exception as e:
            print(f"[-] Search error: {e}")

        return search_info

    # =========================================================================
    # REPLAY SERVICE OPERATIONS
    # =========================================================================

    def _get_replay_service(self):
        """Get or create replay service."""
        if not self._replay_service:
            try:
                self._replay_service = self.camera.create_replay_service()
                self._patch_service_binding(self._replay_service)
            except Exception:
                pass
        return self._replay_service

    def get_replay_uri(self, recording_token: str = None) -> dict:
        """Get replay URI for recordings."""
        print("\n[*] Replay URIs")
        print("-" * 50)
        replay_service = self._get_replay_service()
        if not replay_service:
            print("[-] Replay service not available")
            return {}

        replay_info = {'uris': []}

        try:
            # Get replay service capabilities
            caps = replay_service.GetServiceCapabilities()
            replay_info['capabilities'] = {
                'reverse_playback': getattr(caps, 'ReversePlayback', False),
                'rtp_rtsp_tcp': getattr(caps, 'RTP_RTSP_TCP', False),
            }
            print(f"  [+] Capabilities: ReversePlayback={replay_info['capabilities']['reverse_playback']}")

            # Get recordings if not provided
            if not recording_token:
                recording_service = self._get_recording_service()
                if recording_service:
                    recordings = recording_service.GetRecordings()
                    if recordings:
                        recording_token = recordings[0].RecordingToken

            if recording_token:
                # Get replay URI
                stream_setup = {
                    'Stream': 'RTP-Unicast',
                    'Transport': {'Protocol': 'RTSP'}
                }
                uri_response = replay_service.GetReplayUri({
                    'StreamSetup': stream_setup,
                    'RecordingToken': recording_token
                })

                uri = getattr(uri_response, 'Uri', None)
                if uri:
                    replay_info['uris'].append({
                        'recording_token': recording_token,
                        'uri': uri
                    })
                    print(f"  [+] Replay URI: {uri}")

            self.results.replay = replay_info
        except Exception as e:
            print(f"[-] Replay error: {e}")

        return replay_info

    def get_replay_configuration(self) -> dict:
        """Get replay configuration."""
        replay_service = self._get_replay_service()
        if not replay_service:
            return {}

        try:
            config = replay_service.GetReplayConfiguration()
            return {
                'session_timeout': str(getattr(config, 'SessionTimeout', 'N/A')),
            }
        except Exception:
            return {}

    # =========================================================================
    # EXTENDED ONVIF SERVICES
    # =========================================================================

    def _get_doorcontrol_service(self):
        """Get or create door control service."""
        if not self._doorcontrol_service:
            try:
                self._doorcontrol_service = self.camera.create_doorcontrol_service()
                self._patch_service_binding(self._doorcontrol_service)
            except Exception:
                pass
        return self._doorcontrol_service

    def get_doorcontrol_capabilities(self) -> dict:
        """Get door control service capabilities."""
        print("\n[*] Door Control Service Capabilities")
        print("-" * 50)
        doorcontrol_service = self._get_doorcontrol_service()
        if not doorcontrol_service:
            print("[-] Door Control service not available")
            return {}

        capabilities = {}
        try:
            caps = doorcontrol_service.GetServiceCapabilities()
            capabilities = {
                'max_limit': getattr(caps, 'MaxLimit', 'N/A'),
            }
            print(f"  [+] MaxLimit: {capabilities['max_limit']}")

            # Try to get door info list
            try:
                doors = doorcontrol_service.GetDoorInfoList({'Limit': 100, 'StartReference': ''})
                door_list = []
                for door in doors:
                    door_info = {
                        'token': getattr(door, 'token', 'N/A'),
                        'name': getattr(door, 'Name', 'N/A'),
                        'description': getattr(door, 'Description', 'N/A'),
                    }
                    door_list.append(door_info)
                    print(f"  [+] Door: {door_info['name']} (Token: {door_info['token']})")
                capabilities['doors'] = door_list
            except Exception as e:
                print(f"  [-] Could not enumerate doors: {e}")

        except Exception as e:
            print(f"[-] Door Control error: {e}")

        return capabilities

    def _get_accesscontrol_service(self):
        """Get or create access control service."""
        if not self._accesscontrol_service:
            try:
                self._accesscontrol_service = self.camera.create_accesscontrol_service()
                self._patch_service_binding(self._accesscontrol_service)
            except Exception:
                pass
        return self._accesscontrol_service

    def get_accesscontrol_capabilities(self) -> dict:
        """Get access control service capabilities."""
        print("\n[*] Access Control Service Capabilities")
        print("-" * 50)
        accesscontrol_service = self._get_accesscontrol_service()
        if not accesscontrol_service:
            print("[-] Access Control service not available")
            return {}

        capabilities = {}
        try:
            caps = accesscontrol_service.GetServiceCapabilities()
            capabilities = {
                'max_limit': getattr(caps, 'MaxLimit', 'N/A'),
                'client_supplied_token_supported': getattr(caps, 'ClientSuppliedTokenSupported', False),
            }
            print(f"  [+] MaxLimit: {capabilities['max_limit']}")
            print(f"  [+] ClientSuppliedTokenSupported: {capabilities['client_supplied_token_supported']}")

            # Try to get access point info
            try:
                access_points = accesscontrol_service.GetAccessPointInfoList({'Limit': 100, 'StartReference': ''})
                ap_list = []
                for ap in access_points:
                    ap_info = {
                        'token': getattr(ap, 'token', 'N/A'),
                        'name': getattr(ap, 'Name', 'N/A'),
                        'description': getattr(ap, 'Description', 'N/A'),
                        'area_from': getattr(ap, 'AreaFrom', 'N/A'),
                        'area_to': getattr(ap, 'AreaTo', 'N/A'),
                    }
                    ap_list.append(ap_info)
                    print(f"  [+] Access Point: {ap_info['name']} (Token: {ap_info['token']})")
                capabilities['access_points'] = ap_list
            except Exception as e:
                print(f"  [-] Could not enumerate access points: {e}")

            # Try to get area info
            try:
                areas = accesscontrol_service.GetAreaInfoList({'Limit': 100, 'StartReference': ''})
                area_list = []
                for area in areas:
                    area_info = {
                        'token': getattr(area, 'token', 'N/A'),
                        'name': getattr(area, 'Name', 'N/A'),
                        'description': getattr(area, 'Description', 'N/A'),
                    }
                    area_list.append(area_info)
                    print(f"  [+] Area: {area_info['name']} (Token: {area_info['token']})")
                capabilities['areas'] = area_list
            except Exception as e:
                print(f"  [-] Could not enumerate areas: {e}")

        except Exception as e:
            print(f"[-] Access Control error: {e}")

        return capabilities

    def _get_thermal_service(self):
        """Get or create thermal service."""
        if not self._thermal_service:
            try:
                self._thermal_service = self.camera.create_thermal_service()
                self._patch_service_binding(self._thermal_service)
            except Exception:
                pass
        return self._thermal_service

    def get_thermal_capabilities(self) -> dict:
        """Get thermal service capabilities."""
        print("\n[*] Thermal Service Capabilities")
        print("-" * 50)
        thermal_service = self._get_thermal_service()
        if not thermal_service:
            print("[-] Thermal service not available")
            return {}

        capabilities = {}
        try:
            caps = thermal_service.GetServiceCapabilities()
            capabilities = {
                'radiometry': getattr(caps, 'Radiometry', False),
            }
            print(f"  [+] Radiometry: {capabilities['radiometry']}")

            # Try to get configurations
            try:
                configs = thermal_service.GetConfigurations()
                config_list = []
                for config in configs:
                    config_info = {
                        'token': getattr(config, 'token', 'N/A'),
                        'name': getattr(config, 'Name', 'N/A'),
                    }
                    config_list.append(config_info)
                    print(f"  [+] Thermal Config: {config_info['name']} (Token: {config_info['token']})")
                capabilities['configurations'] = config_list
            except Exception as e:
                print(f"  [-] Could not enumerate thermal configurations: {e}")

        except Exception as e:
            print(f"[-] Thermal service error: {e}")

        return capabilities

    def _get_deviceio_service(self):
        """Get or create device IO service."""
        if not self._deviceio_service:
            try:
                self._deviceio_service = self.camera.create_deviceio_service()
                self._patch_service_binding(self._deviceio_service)
            except Exception:
                pass
        return self._deviceio_service

    def get_deviceio_capabilities(self) -> dict:
        """Get device IO service capabilities."""
        print("\n[*] Device IO Service Capabilities")
        print("-" * 50)
        deviceio_service = self._get_deviceio_service()
        if not deviceio_service:
            print("[-] Device IO service not available")
            return {}

        capabilities = {}
        try:
            caps = deviceio_service.GetServiceCapabilities()
            capabilities = {
                'video_sources': getattr(caps, 'VideoSources', 0),
                'video_outputs': getattr(caps, 'VideoOutputs', 0),
                'audio_sources': getattr(caps, 'AudioSources', 0),
                'audio_outputs': getattr(caps, 'AudioOutputs', 0),
                'relay_outputs': getattr(caps, 'RelayOutputs', 0),
                'serial_ports': getattr(caps, 'SerialPorts', 0),
                'digital_inputs': getattr(caps, 'DigitalInputs', 0),
                'digital_input_options': getattr(caps, 'DigitalInputOptions', False),
            }
            for key, value in capabilities.items():
                print(f"  [+] {key}: {value}")

            # Try to get relay outputs
            try:
                relay_outputs = deviceio_service.GetRelayOutputs()
                relay_list = []
                for relay in relay_outputs:
                    relay_info = {
                        'token': getattr(relay, 'token', 'N/A'),
                        'mode': str(getattr(relay.Properties, 'Mode', 'N/A')) if hasattr(relay, 'Properties') else 'N/A',
                        'delay_time': str(getattr(relay.Properties, 'DelayTime', 'N/A')) if hasattr(relay, 'Properties') else 'N/A',
                        'idle_state': str(getattr(relay.Properties, 'IdleState', 'N/A')) if hasattr(relay, 'Properties') else 'N/A',
                    }
                    relay_list.append(relay_info)
                    print(f"  [+] Relay Output: {relay_info['token']} (Mode: {relay_info['mode']}, IdleState: {relay_info['idle_state']})")
                capabilities['relay_outputs_list'] = relay_list
            except Exception as e:
                print(f"  [-] Could not enumerate relay outputs: {e}")

            # Try to get digital inputs
            try:
                digital_inputs = deviceio_service.GetDigitalInputs()
                di_list = []
                for di in digital_inputs:
                    di_info = {
                        'token': getattr(di, 'token', 'N/A'),
                    }
                    di_list.append(di_info)
                    print(f"  [+] Digital Input: {di_info['token']}")
                capabilities['digital_inputs_list'] = di_list
            except Exception as e:
                print(f"  [-] Could not enumerate digital inputs: {e}")

            # Try to get serial ports
            try:
                serial_ports = deviceio_service.GetSerialPorts()
                sp_list = []
                for sp in serial_ports:
                    sp_info = {
                        'token': getattr(sp, 'token', 'N/A'),
                    }
                    sp_list.append(sp_info)
                    print(f"  [+] Serial Port: {sp_info['token']}")
                capabilities['serial_ports_list'] = sp_list
            except Exception as e:
                print(f"  [-] Could not enumerate serial ports: {e}")

        except Exception as e:
            print(f"[-] Device IO error: {e}")

        return capabilities

    def _get_credential_service(self):
        """Get or create credential service."""
        if not self._credential_service:
            try:
                self._credential_service = self.camera.create_credential_service()
                self._patch_service_binding(self._credential_service)
            except Exception:
                pass
        return self._credential_service

    def get_credential_capabilities(self) -> dict:
        """Get credential service capabilities."""
        print("\n[*] Credential Service Capabilities")
        print("-" * 50)
        credential_service = self._get_credential_service()
        if not credential_service:
            print("[-] Credential service not available")
            return {}

        capabilities = {}
        try:
            caps = credential_service.GetServiceCapabilities()
            capabilities = {
                'max_limit': getattr(caps, 'MaxLimit', 'N/A'),
                'max_credentials': getattr(caps, 'MaxCredentials', 'N/A'),
                'credential_access_profile_validity': getattr(caps, 'CredentialAccessProfileValiditySupported', False),
                'credential_validity': getattr(caps, 'CredentialValiditySupported', False),
                'reset_antipassback': getattr(caps, 'ResetAntipassbackSupported', False),
                'supported_identifier_type': getattr(caps, 'SupportedIdentifierType', []),
            }
            for key, value in capabilities.items():
                print(f"  [+] {key}: {value}")

            # Try to get credential info list
            try:
                creds = credential_service.GetCredentialInfoList({'Limit': 100, 'StartReference': ''})
                cred_list = []
                for cred in creds:
                    cred_info = {
                        'token': getattr(cred, 'token', 'N/A'),
                        'description': getattr(cred, 'Description', 'N/A'),
                    }
                    cred_list.append(cred_info)
                    print(f"  [+] Credential: {cred_info['token']}")
                capabilities['credentials'] = cred_list
            except Exception as e:
                print(f"  [-] Could not enumerate credentials: {e}")

        except Exception as e:
            print(f"[-] Credential service error: {e}")

        return capabilities

    def _get_accessrules_service(self):
        """Get or create access rules service."""
        if not self._accessrules_service:
            try:
                self._accessrules_service = self.camera.create_accessrules_service()
                self._patch_service_binding(self._accessrules_service)
            except Exception:
                pass
        return self._accessrules_service

    def get_accessrules_capabilities(self) -> dict:
        """Get access rules service capabilities."""
        print("\n[*] Access Rules Service Capabilities")
        print("-" * 50)
        accessrules_service = self._get_accessrules_service()
        if not accessrules_service:
            print("[-] Access Rules service not available")
            return {}

        capabilities = {}
        try:
            caps = accessrules_service.GetServiceCapabilities()
            capabilities = {
                'max_limit': getattr(caps, 'MaxLimit', 'N/A'),
                'access_profile_validity_level': getattr(caps, 'AccessProfileValidityLevelSupported', False),
            }
            for key, value in capabilities.items():
                print(f"  [+] {key}: {value}")

            # Try to get access profile info list
            try:
                profiles = accessrules_service.GetAccessProfileInfoList({'Limit': 100, 'StartReference': ''})
                profile_list = []
                for profile in profiles:
                    profile_info = {
                        'token': getattr(profile, 'token', 'N/A'),
                        'name': getattr(profile, 'Name', 'N/A'),
                        'description': getattr(profile, 'Description', 'N/A'),
                    }
                    profile_list.append(profile_info)
                    print(f"  [+] Access Profile: {profile_info['name']} (Token: {profile_info['token']})")
                capabilities['access_profiles'] = profile_list
            except Exception as e:
                print(f"  [-] Could not enumerate access profiles: {e}")

        except Exception as e:
            print(f"[-] Access Rules error: {e}")

        return capabilities

    def _get_schedule_service(self):
        """Get or create schedule service."""
        if not self._schedule_service:
            try:
                self._schedule_service = self.camera.create_schedule_service()
                self._patch_service_binding(self._schedule_service)
            except Exception:
                pass
        return self._schedule_service

    def get_schedule_capabilities(self) -> dict:
        """Get schedule service capabilities."""
        print("\n[*] Schedule Service Capabilities")
        print("-" * 50)
        schedule_service = self._get_schedule_service()
        if not schedule_service:
            print("[-] Schedule service not available")
            return {}

        capabilities = {}
        try:
            caps = schedule_service.GetServiceCapabilities()
            capabilities = {
                'max_limit': getattr(caps, 'MaxLimit', 'N/A'),
                'max_schedules': getattr(caps, 'MaxSchedules', 'N/A'),
                'max_time_periods_per_day': getattr(caps, 'MaxTimePeriodsPerDay', 'N/A'),
                'max_special_day_groups': getattr(caps, 'MaxSpecialDayGroups', 'N/A'),
                'max_days_in_special_day_group': getattr(caps, 'MaxDaysInSpecialDayGroup', 'N/A'),
                'max_special_days_schedules': getattr(caps, 'MaxSpecialDaysSchedules', 'N/A'),
            }
            for key, value in capabilities.items():
                print(f"  [+] {key}: {value}")

            # Try to get schedule info list
            try:
                schedules = schedule_service.GetScheduleInfoList({'Limit': 100, 'StartReference': ''})
                schedule_list = []
                for schedule in schedules:
                    schedule_info = {
                        'token': getattr(schedule, 'token', 'N/A'),
                        'name': getattr(schedule, 'Name', 'N/A'),
                        'description': getattr(schedule, 'Description', 'N/A'),
                    }
                    schedule_list.append(schedule_info)
                    print(f"  [+] Schedule: {schedule_info['name']} (Token: {schedule_info['token']})")
                capabilities['schedules'] = schedule_list
            except Exception as e:
                print(f"  [-] Could not enumerate schedules: {e}")

            # Try to get special day group info list
            try:
                special_days = schedule_service.GetSpecialDayGroupInfoList({'Limit': 100, 'StartReference': ''})
                sd_list = []
                for sd in special_days:
                    sd_info = {
                        'token': getattr(sd, 'token', 'N/A'),
                        'name': getattr(sd, 'Name', 'N/A'),
                    }
                    sd_list.append(sd_info)
                    print(f"  [+] Special Day Group: {sd_info['name']} (Token: {sd_info['token']})")
                capabilities['special_day_groups'] = sd_list
            except Exception as e:
                print(f"  [-] Could not enumerate special day groups: {e}")

        except Exception as e:
            print(f"[-] Schedule service error: {e}")

        return capabilities

    def _get_receiver_service(self):
        """Get or create receiver service."""
        if not self._receiver_service:
            try:
                self._receiver_service = self.camera.create_receiver_service()
                self._patch_service_binding(self._receiver_service)
            except Exception:
                pass
        return self._receiver_service

    def get_receiver_capabilities(self) -> dict:
        """Get receiver service capabilities."""
        print("\n[*] Receiver Service Capabilities")
        print("-" * 50)
        receiver_service = self._get_receiver_service()
        if not receiver_service:
            print("[-] Receiver service not available")
            return {}

        capabilities = {}
        try:
            caps = receiver_service.GetServiceCapabilities()
            capabilities = {
                'rtp_multicast': getattr(caps, 'RTP_Multicast', False),
                'rtp_tcp': getattr(caps, 'RTP_TCP', False),
                'rtp_rtsp_tcp': getattr(caps, 'RTP_RTSP_TCP', False),
                'supported_receivers': getattr(caps, 'SupportedReceivers', 0),
                'maximum_rtsp_uri_length': getattr(caps, 'MaximumRTSPURILength', 0),
            }
            for key, value in capabilities.items():
                print(f"  [+] {key}: {value}")

            # Try to get receivers
            try:
                receivers = receiver_service.GetReceivers()
                receiver_list = []
                for receiver in receivers:
                    receiver_info = {
                        'token': getattr(receiver, 'Token', 'N/A'),
                        'configuration': {
                            'mode': str(getattr(receiver.Configuration, 'Mode', 'N/A')) if hasattr(receiver, 'Configuration') else 'N/A',
                            'media_uri': getattr(receiver.Configuration, 'MediaUri', 'N/A') if hasattr(receiver, 'Configuration') else 'N/A',
                        }
                    }
                    receiver_list.append(receiver_info)
                    print(f"  [+] Receiver: {receiver_info['token']} (Mode: {receiver_info['configuration']['mode']})")
                    if receiver_info['configuration']['media_uri'] != 'N/A':
                        print(f"       URI: {receiver_info['configuration']['media_uri']}")
                capabilities['receivers'] = receiver_list
            except Exception as e:
                print(f"  [-] Could not enumerate receivers: {e}")

        except Exception as e:
            print(f"[-] Receiver service error: {e}")

        return capabilities

    def _get_provisioning_service(self):
        """Get or create provisioning service."""
        if not self._provisioning_service:
            try:
                self._provisioning_service = self.camera.create_provisioning_service()
                self._patch_service_binding(self._provisioning_service)
            except Exception:
                pass
        return self._provisioning_service

    def get_provisioning_capabilities(self) -> dict:
        """Get provisioning service capabilities."""
        print("\n[*] Provisioning Service Capabilities")
        print("-" * 50)
        provisioning_service = self._get_provisioning_service()
        if not provisioning_service:
            print("[-] Provisioning service not available")
            return {}

        capabilities = {}
        try:
            caps = provisioning_service.GetServiceCapabilities()
            # Extract available capabilities
            if hasattr(caps, 'DefaultGatewaySupported'):
                capabilities['default_gateway_supported'] = caps.DefaultGatewaySupported
            if hasattr(caps, 'FocusMoveSupported'):
                capabilities['focus_move_supported'] = caps.FocusMoveSupported
            if hasattr(caps, 'ZoomSupported'):
                capabilities['zoom_supported'] = caps.ZoomSupported
            if hasattr(caps, 'MaximumPanMoveSupported'):
                capabilities['max_pan_move_supported'] = caps.MaximumPanMoveSupported
            if hasattr(caps, 'MaximumTiltMoveSupported'):
                capabilities['max_tilt_move_supported'] = caps.MaximumTiltMoveSupported
            if hasattr(caps, 'MaximumRollMoveSupported'):
                capabilities['max_roll_move_supported'] = caps.MaximumRollMoveSupported

            for key, value in capabilities.items():
                print(f"  [+] {key}: {value}")

            # Try to get usage
            try:
                usage = provisioning_service.GetUsage()
                if usage:
                    capabilities['usage'] = str(usage)
                    print(f"  [+] Usage: {usage}")
            except Exception:
                pass

        except Exception as e:
            print(f"[-] Provisioning service error: {e}")

        return capabilities

    def get_all_extended_services(self) -> dict:
        """Get capabilities from all extended ONVIF services."""
        print("\n" + "=" * 60)
        print("EXTENDED ONVIF SERVICES ENUMERATION")
        print("=" * 60)

        results = {}
        results['doorcontrol'] = self.get_doorcontrol_capabilities()
        results['accesscontrol'] = self.get_accesscontrol_capabilities()
        results['thermal'] = self.get_thermal_capabilities()
        results['deviceio'] = self.get_deviceio_capabilities()
        results['credential'] = self.get_credential_capabilities()
        results['accessrules'] = self.get_accessrules_capabilities()
        results['schedule'] = self.get_schedule_capabilities()
        results['receiver'] = self.get_receiver_capabilities()
        results['provisioning'] = self.get_provisioning_capabilities()

        return results

    # =========================================================================
    # SECURITY ASSESSMENT
    # =========================================================================

    def check_security(self) -> dict:
        """Comprehensive security assessment."""
        print("\n[*] Security Assessment")
        print("-" * 50)
        security_info = {}

        # Check for default/weak credentials
        default_creds = [
            ('admin', 'admin'), ('admin', ''), ('admin', '12345'),
            ('admin', '123456'), ('admin', '1234'), ('admin', 'password'),
            ('root', 'root'), ('root', ''), ('user', 'user'),
        ]

        print("  [*] Credential Analysis...")
        if self.target.username == 'admin' and self.target.password in ['admin', '', '12345', '123456', '1234', 'password']:
            print("  [!] WARNING: Using common default credentials!")
            security_info['default_creds'] = True
        else:
            security_info['default_creds'] = False
            print("  [+] Non-default credentials in use")

        # Check authentication methods
        print("\n  [*] Authentication Methods...")
        try:
            svc_caps = self._device_service.GetServiceCapabilities()
            if hasattr(svc_caps, 'Security') and svc_caps.Security:
                sec = svc_caps.Security
                security_info['auth_methods'] = {
                    'username_token': getattr(sec, 'UsernameToken', False),
                    'http_digest': getattr(sec, 'HttpDigest', False),
                    'x509_token': getattr(sec, 'X_509Token', False),
                    'saml_token': getattr(sec, 'SAMLToken', False),
                    'kerberos_token': getattr(sec, 'KerberosToken', False),
                    'dot1x': getattr(sec, 'Dot1X', False),
                }
                for method, enabled in security_info['auth_methods'].items():
                    status = "Enabled" if enabled else "Disabled"
                    print(f"      {method}: {status}")
        except Exception:
            pass

        # Check TLS support
        print("\n  [*] TLS Support...")
        try:
            if hasattr(svc_caps, 'Security') and svc_caps.Security:
                sec = svc_caps.Security
                security_info['tls'] = {
                    'tls_1_0': getattr(sec, 'TLS1_0', False),
                    'tls_1_1': getattr(sec, 'TLS1_1', False),
                    'tls_1_2': getattr(sec, 'TLS1_2', False),
                }
                for ver, enabled in security_info['tls'].items():
                    if enabled:
                        print(f"      {ver.replace('_', '.')}: Supported")
                if not any(security_info['tls'].values()):
                    print("  [!] WARNING: No TLS support detected!")
        except Exception:
            pass

        # Check user enumeration
        print("\n  [*] User Accounts...")
        try:
            users = self._device_service.GetUsers()
            security_info['user_count'] = len(users)
            admin_users = [u for u in users if str(getattr(u, 'UserLevel', '')).lower() in ['administrator', 'admin']]
            security_info['admin_count'] = len(admin_users)
            print(f"      Total Users: {security_info['user_count']}")
            print(f"      Admin Users: {security_info['admin_count']}")
            if security_info['admin_count'] > 1:
                print("  [!] WARNING: Multiple administrator accounts")
        except Exception:
            pass

        # Check network exposure
        print("\n  [*] Network Exposure...")
        try:
            interfaces = self._device_service.GetNetworkInterfaces()
            exposed_interfaces = 0
            for iface in interfaces:
                if getattr(iface, 'Enabled', False):
                    exposed_interfaces += 1
            security_info['exposed_interfaces'] = exposed_interfaces
            print(f"      Enabled Interfaces: {exposed_interfaces}")
        except Exception:
            pass

        # Check protocols
        print("\n  [*] Enabled Protocols...")
        try:
            protocols = self._device_service.GetNetworkProtocols()
            security_info['protocols'] = {}
            for proto in protocols:
                name = getattr(proto, 'Name', 'Unknown')
                enabled = getattr(proto, 'Enabled', False)
                if enabled:
                    security_info['protocols'][name] = True
                    print(f"      {name}: Enabled")
                    if name.upper() in ['HTTP', 'TELNET', 'FTP']:
                        print(f"  [!] WARNING: Insecure protocol {name} is enabled!")
        except Exception:
            pass

        # Check certificate status
        print("\n  [*] Certificates...")
        try:
            certs = self._device_service.GetCertificates()
            security_info['certificate_count'] = len(certs)
            print(f"      Installed Certificates: {len(certs)}")
            if len(certs) == 0:
                print("  [!] WARNING: No certificates installed")
        except Exception:
            print("      Certificate enumeration not available")

        # Check IP filtering
        print("\n  [*] IP Address Filtering...")
        try:
            ip_filter = self._device_service.GetIPAddressFilter()
            filter_type = getattr(ip_filter, 'Type', 'N/A')
            security_info['ip_filter_type'] = str(filter_type)
            print(f"      Filter Type: {filter_type}")
            if str(filter_type).lower() == 'accept':
                # Count filtered addresses
                addr_count = 0
                if hasattr(ip_filter, 'IPv4Address'):
                    addr_count += len(ip_filter.IPv4Address) if ip_filter.IPv4Address else 0
                if hasattr(ip_filter, 'IPv6Address'):
                    addr_count += len(ip_filter.IPv6Address) if ip_filter.IPv6Address else 0
                print(f"      Filtered Addresses: {addr_count}")
                if addr_count == 0:
                    print("  [!] WARNING: Accept filter with no addresses (blocks all)")
        except Exception:
            print("      IP filtering not available")

        # Summary
        print("\n  [*] Security Summary")
        print("-" * 50)
        issues = []
        if security_info.get('default_creds'):
            issues.append("Default/weak credentials")
        if security_info.get('tls') and not any(security_info['tls'].values()):
            issues.append("No TLS support")
        if security_info.get('admin_count', 0) > 1:
            issues.append("Multiple admin accounts")
        if security_info.get('protocols', {}).get('HTTP') or security_info.get('protocols', {}).get('TELNET'):
            issues.append("Insecure protocols enabled")
        if security_info.get('certificate_count', 0) == 0:
            issues.append("No certificates installed")

        if issues:
            print(f"  [!] Issues Found: {len(issues)}")
            for issue in issues:
                print(f"      - {issue}")
            security_info['issues'] = issues
        else:
            print("  [+] No major issues detected")

        self.results.security = security_info
        return security_info

    # =========================================================================
    # FULL ENUMERATION
    # =========================================================================

    def enumerate_all(self, include_optional: bool = True) -> EnumerationResults:
        """Run comprehensive enumeration."""
        if not self.connect():
            return self.results

        # Core device info
        self.get_device_info()
        self.get_wsdl_url()
        self.get_capabilities()
        self.get_services()
        self.get_service_capabilities()
        self.get_scopes()
        self.get_discovery_mode()
        self.get_endpoint_reference()

        # Network configuration
        self.get_network_interfaces()
        self.get_network_protocols()
        self.get_network_default_gateway()
        self.get_dns()
        self.get_ntp()
        self.get_dynamic_dns()
        self.get_zero_configuration()
        self.get_hostname()
        self.get_system_date_time()

        # Users and security
        self.get_users()
        self.get_certificates()
        self.get_access_policy()
        self.get_ip_address_filter()

        # I/O
        self.get_relay_outputs()
        self.get_digital_inputs()

        # Media
        self.get_profiles()
        self.get_video_sources()
        self.get_video_source_configurations()
        self.get_audio_sources()
        self.get_audio_outputs()
        self.get_video_encoder_configurations()
        self.get_audio_encoder_configurations()
        self.get_osds()
        self.get_metadata_configurations()

        # PTZ
        self.get_ptz_capabilities()

        # Imaging
        self.get_imaging_settings()

        # Events
        self.get_event_properties()
        self.get_event_service_capabilities()

        # Analytics
        self.get_analytics_capabilities()

        # Recording/Search/Replay
        self.get_recordings()
        self.get_recording_search_results()
        self.get_replay_uri()

        # Optional: System logs (can be slow/large)
        if include_optional:
            self.get_system_log()
            self.get_system_support_information()
            self.get_geo_location()

        # Extended Services (if available)
        if include_optional:
            self.get_all_extended_services()

        # Security assessment
        self.check_security()

        return self.results

    def enumerate_quick(self) -> EnumerationResults:
        """Quick enumeration - core info only."""
        if not self.connect():
            return self.results

        self.get_device_info()
        self.get_capabilities()
        self.get_services()
        self.get_profiles()
        self.check_security()

        return self.results


def probe_onvif(ip: str, port: int = 80, timeout: int = 3) -> bool:
    """Quick probe to check if ONVIF service is available."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def interactive_menu(enumerator: ONVIFEnumerator):
    """Interactive menu for selecting ONVIF operations."""

    # Define operation categories and their methods
    operations = {
        'Device Service': [
            ('1', 'Get Device Information', enumerator.get_device_info),
            ('2', 'Get WSDL URL', enumerator.get_wsdl_url),
            ('3', 'Get Capabilities', enumerator.get_capabilities),
            ('4', 'Get Services', enumerator.get_services),
            ('5', 'Get Service Capabilities', enumerator.get_service_capabilities),
            ('6', 'Get Scopes', enumerator.get_scopes),
            ('7', 'Get Discovery Mode', enumerator.get_discovery_mode),
            ('8', 'Get Endpoint Reference', enumerator.get_endpoint_reference),
            ('9', 'Get Hostname', enumerator.get_hostname),
            ('10', 'Get System Date/Time', enumerator.get_system_date_time),
            ('11', 'Get System Log', enumerator.get_system_log),
            ('12', 'Get Support Information', enumerator.get_system_support_information),
            ('13', 'Get Geo Location', enumerator.get_geo_location),
            ('14', 'Get System Backup', enumerator.get_system_backup),
            ('15', 'Check Firmware Upgrade', enumerator.get_firmware_upgrade_info),
        ],
        'Network': [
            ('20', 'Get Network Interfaces', enumerator.get_network_interfaces),
            ('21', 'Get Network Protocols', enumerator.get_network_protocols),
            ('22', 'Get Default Gateway', enumerator.get_network_default_gateway),
            ('23', 'Get DNS', enumerator.get_dns),
            ('24', 'Get NTP', enumerator.get_ntp),
            ('25', 'Get Dynamic DNS', enumerator.get_dynamic_dns),
            ('26', 'Get Zero Configuration', enumerator.get_zero_configuration),
        ],
        'Users & Security': [
            ('30', 'Get Users', enumerator.get_users),
            ('31', 'Get Certificates', enumerator.get_certificates),
            ('32', 'Get Access Policy', enumerator.get_access_policy),
            ('33', 'Get IP Address Filter', enumerator.get_ip_address_filter),
            ('34', 'Security Assessment', enumerator.check_security),
        ],
        'I/O': [
            ('40', 'Get Relay Outputs', enumerator.get_relay_outputs),
            ('41', 'Get Digital Inputs', enumerator.get_digital_inputs),
        ],
        'Media': [
            ('50', 'Get Profiles (with stream URIs)', enumerator.get_profiles),
            ('51', 'Get Video Sources', enumerator.get_video_sources),
            ('52', 'Get Video Source Configurations', enumerator.get_video_source_configurations),
            ('53', 'Get Audio Sources', enumerator.get_audio_sources),
            ('54', 'Get Audio Outputs', enumerator.get_audio_outputs),
            ('55', 'Get Video Encoder Configurations', enumerator.get_video_encoder_configurations),
            ('56', 'Get Audio Encoder Configurations', enumerator.get_audio_encoder_configurations),
            ('57', 'Get OSDs', enumerator.get_osds),
            ('58', 'Get Metadata Configurations', enumerator.get_metadata_configurations),
        ],
        'PTZ': [
            ('60', 'Get PTZ Capabilities', enumerator.get_ptz_capabilities),
        ],
        'Imaging': [
            ('70', 'Get Imaging Settings', enumerator.get_imaging_settings),
        ],
        'Events': [
            ('80', 'Get Event Properties', enumerator.get_event_properties),
            ('81', 'Get Event Service Capabilities', enumerator.get_event_service_capabilities),
            ('82', 'Create Pull Point Subscription', enumerator.create_pull_point_subscription),
        ],
        'Analytics': [
            ('90', 'Get Analytics Capabilities', enumerator.get_analytics_capabilities),
        ],
        'Recording/Search/Replay': [
            ('100', 'Get Recordings', enumerator.get_recordings),
            ('101', 'Get Recording Search Results', enumerator.get_recording_search_results),
            ('102', 'Get Replay URI', enumerator.get_replay_uri),
        ],
        'Extended Services': [
            ('110', 'Door Control Capabilities', enumerator.get_doorcontrol_capabilities),
            ('111', 'Access Control Capabilities', enumerator.get_accesscontrol_capabilities),
            ('112', 'Thermal Service Capabilities', enumerator.get_thermal_capabilities),
            ('113', 'Device IO Capabilities', enumerator.get_deviceio_capabilities),
            ('114', 'Credential Service Capabilities', enumerator.get_credential_capabilities),
            ('115', 'Access Rules Capabilities', enumerator.get_accessrules_capabilities),
            ('116', 'Schedule Service Capabilities', enumerator.get_schedule_capabilities),
            ('117', 'Receiver Service Capabilities', enumerator.get_receiver_capabilities),
            ('118', 'Provisioning Service Capabilities', enumerator.get_provisioning_capabilities),
            ('119', 'All Extended Services', enumerator.get_all_extended_services),
        ],
        'Full Scans': [
            ('A', 'Run ALL Operations (Full Scan)', lambda: enumerator.enumerate_all(include_optional=True)),
            ('Q', 'Quick Scan (Core Info Only)', enumerator.enumerate_quick),
        ],
    }

    # Build lookup dict
    op_lookup = {}
    for category, ops in operations.items():
        for code, name, func in ops:
            op_lookup[code.upper()] = (name, func)

    while True:
        print("\n" + "=" * 60)
        print("ONVIF Interactive Menu")
        print("=" * 60)

        for category, ops in operations.items():
            print(f"\n  [{category}]")
            for code, name, _ in ops:
                print(f"    {code:>4}. {name}")

        print(f"\n  [Navigation]")
        print(f"    {'H':>4}. Show this menu")
        print(f"    {'X':>4}. Exit interactive mode")

        print("\n" + "-" * 60)
        choice = input("Select operation(s) [comma-separated or range, e.g., 1,2,3 or 50-58]: ").strip().upper()

        if choice == 'X':
            print("\n[*] Exiting interactive mode...")
            break
        elif choice == 'H':
            continue
        elif not choice:
            continue

        # Parse selection (supports comma-separated and ranges)
        selections = []
        for part in choice.split(','):
            part = part.strip()
            if '-' in part and not part.startswith('-'):
                try:
                    start, end = part.split('-')
                    for i in range(int(start), int(end) + 1):
                        selections.append(str(i))
                except ValueError:
                    selections.append(part)
            else:
                selections.append(part)

        # Execute selected operations
        for sel in selections:
            sel = sel.upper()
            if sel in op_lookup:
                name, func = op_lookup[sel]
                print(f"\n{'=' * 60}")
                print(f"[*] Executing: {name}")
                print('=' * 60)
                try:
                    result = func()
                    if result and isinstance(result, (dict, list)):
                        print(f"\n[+] Operation completed successfully")
                except Exception as e:
                    print(f"[-] Error: {e}")
            else:
                print(f"[-] Unknown option: {sel}")

        input("\nPress Enter to continue...")


def main():
    parser = argparse.ArgumentParser(
        description='ONVIF Device Enumerator - Comprehensive IP camera enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s 192.168.1.100                              # Full scan
  %(prog)s 192.168.1.100 -i                           # Interactive mode
  %(prog)s 192.168.1.100 -u admin --password secret   # Custom credentials
  %(prog)s 192.168.1.100 --port 8000                  # Custom port
  %(prog)s 192.168.1.100 --quick                      # Quick scan
  %(prog)s 192.168.1.100 --json -o results.json       # Save as JSON

Interactive mode (-i):
  Select individual operations from a menu. Supports:
  - Single selection: 1
  - Multiple selections: 1,2,3
  - Ranges: 50-58
  - Combined: 1,20-26,50

Common default credentials:
  admin:admin, admin:12345, admin:123456, root:root
        '''
    )

    parser.add_argument('ip', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=80, help='ONVIF port (default: 80)')
    parser.add_argument('-u', '--username', default='admin', help='Username (default: admin)')
    parser.add_argument('--password', default='admin', help='Password (default: admin)')
    parser.add_argument('--wsdl', help='Custom WSDL directory path')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan (core info only)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode - select operations from menu')
    parser.add_argument('--probe', action='store_true', help='Only probe if port is open')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    parser.add_argument('--no-optional', action='store_true', help='Skip optional/slow operations')

    args = parser.parse_args()

    # Parse IP:port format if provided
    if ':' in args.ip:
        parts = args.ip.rsplit(':', 1)
        args.ip = parts[0]
        try:
            args.port = int(parts[1])
        except ValueError:
            print(f"[-] Invalid port: {parts[1]}")
            sys.exit(1)

    print("""
╔═══════════════════════════════════════════════════════════╗
║           ONVIF Device Enumerator v2.0                    ║
║       Comprehensive IP Camera Enumeration                 ║
║       For authorized security testing only                ║
╚═══════════════════════════════════════════════════════════╝
    """)

    # Quick probe
    if args.probe:
        if probe_onvif(args.ip, args.port):
            print(f"[+] {args.ip}:{args.port} - Port open")
            sys.exit(0)
        else:
            print(f"[-] {args.ip}:{args.port} - Port closed or filtered")
            sys.exit(1)

    # Check connectivity first
    if not probe_onvif(args.ip, args.port):
        print(f"[-] Cannot connect to {args.ip}:{args.port}")
        print("[*] Verify the IP, port, and network connectivity")
        sys.exit(1)

    target = ONVIFTarget(
        ip=args.ip,
        port=args.port,
        username=args.username,
        password=args.password,
        wsdl_dir=args.wsdl
    )

    enumerator = ONVIFEnumerator(target)

    # Interactive mode
    if args.interactive:
        if not enumerator.connect():
            print("[-] Failed to connect, cannot enter interactive mode")
            sys.exit(1)
        interactive_menu(enumerator)
        results = enumerator.results
    elif args.quick:
        results = enumerator.enumerate_quick()
    else:
        results = enumerator.enumerate_all(include_optional=not args.no_optional)

    # Output results
    if args.json or args.output:
        results_dict = results.to_dict()
        json_output = json.dumps(results_dict, indent=2, default=str)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"\n[+] Results saved to {args.output}")
        else:
            print("\n" + "=" * 50)
            print("JSON Output:")
            print(json_output)

    print("\n" + "=" * 50)
    print("[*] Enumeration complete")


if __name__ == '__main__':
    main()
