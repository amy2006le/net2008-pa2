# Name: Amy Le Student ID: 101343875
"""NET2008 PA2 - audit a device inventory against a policy."""

import json
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

    def count_interfaces(self):
        """Return how many interfaces are up, down and other."""
        counts = {"up": 0, "down": 0, "other": 0}
        for status in self.interfaces:
            if status in ("up", "down"):
                counts[status] += 1
            else:
                counts["other"] += 1
        return counts


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


def build_report(site, devices, skipped, violations):
    """Put all the results together in the dictionary that becomes audit.json."""
    roles = {}
    interfaces = {"up": 0, "down": 0, "other": 0}
    for device in devices:
        roles[device.role] = roles.get(device.role, 0) + 1
        for group, number in device.count_interfaces().items():
            interfaces[group] += number

    broken = {v["device"] for v in violations}
    compliant = sorted(d.id for d in devices if d.id not in broken)

    return {
        "site": site,
        "total_devices": len(devices),
        "skipped_devices": skipped,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": compliant,
    }


def write_report(report, path):
    """Write the report dictionary to a JSON file."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


def main():
    """Load the inventory, build the report, write audit.json, print a summary."""
    site, devices, skipped = load_devices(sys.argv[1])
    report = build_report(site, devices, skipped, [])
    write_report(report, "audit.json")
    print(f"site: {site}")
    print(f"devices: {len(devices)} kept, {skipped} skipped")


if __name__ == "__main__":
    main()
