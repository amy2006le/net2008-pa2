# Name: Amy Le  Student ID: 101343875
"""NET2008 PA2 - audit a device inventory against a policy."""

import sys
import xml.etree.ElementTree as ET


class AuditError(Exception):
    """Raised when an input file cannot be used."""


class Device:
    """One device from the inventory."""

    def __init__(self, device_id, role, os_version, owner, interfaces):
        """Store the device's attributes."""
        self.id = device_id
        self.role = role
        self.os = os_version
        self.owner = owner
        self.interfaces = interfaces  # list of status strings


def load_devices(path):
    """Read the XML file and return (site, kept_devices, skipped_count)."""
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        raise AuditError(f"{path}: file not found")
    except ET.ParseError:
        raise AuditError(f"{path}: not valid XML")

    devices = []
    skipped = 0
    for element in root.findall("device"):
        device_id = element.get("id")
        if not device_id:
            skipped += 1
            continue
        owner_el = element.find("owner")
        owner = (owner_el.text or "").strip() if owner_el is not None else ""
        statuses = [i.get("status") for i in element.findall("interface")]
        devices.append(
            Device(device_id, element.get("role"), element.get("os"), owner, statuses)
        )
    return root.get("site"), devices, skipped


def main():
    """Temporary main: print the ids of the kept devices."""
    site, devices, skipped = load_devices(sys.argv[1])
    for device in devices:
        print(device.id)
    print("skipped:", skipped)


if __name__ == "__main__":
    main()
