# Name: Amy Le  Student ID: 101343875
"""NET2008 PA2 - audit a device inventory against a policy."""

import json
import sys
import xml.etree.ElementTree as ET

import yaml


class AuditError(Exception):
    """Raised when an input file cannot be used."""


def parse_version(text):
    """Turn '15.10' into (15, 10). Return None if it is not whole numbers."""
    parts = str(text).strip().split(".")
    for part in parts:
        if not (part.isascii() and part.isdigit()):
            return None
    return tuple(int(part) for part in parts)


def is_older(found, required):
    """Return True if version 'found' is lower than 'required'.

    Both are tuples of numbers. The shorter one is padded with zeros,
    so 9.1 equals 9.1.0, and parts are compared as numbers, so 15.10 > 15.2.
    """
    length = max(len(found), len(required))
    found = found + (0,) * (length - len(found))
    required = required + (0,) * (length - len(required))
    return found < required


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

    def check(self, policy):
        """Return the list of policy violations for this device."""
        violations = []

        if "min_os" in policy:
            allowed_roles = policy["min_os"] or {}
            if self.role not in allowed_roles:
                violations.append(
                    {"device": self.id, "type": "unknown_role", "role": self.role}
                )
            else:
                required_text = str(allowed_roles[self.role])
                found = parse_version(self.os)
                required = parse_version(required_text)
                if found is not None and required is not None:
                    if is_older(found, required):
                        violations.append(
                            {
                                "device": self.id,
                                "type": "os_outdated",
                                "found": self.os,
                                "required": required_text,
                            }
                        )

        if policy.get("require_owner") is True and self.owner == "":
            violations.append({"device": self.id, "type": "missing_owner"})

        limit = policy.get("max_down_interfaces")
        if limit is not None:
            down = self.count_interfaces()["down"]
            if down > limit:
                violations.append(
                    {"device": self.id, "type": "too_many_down", "down": down}
                )

        return violations


def load_devices(path):
    """Read the XML file and return (site, kept_devices, skipped_count)."""
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        raise AuditError(f"{path}: file not found")
    except ET.ParseError:
        raise AuditError(f"{path}: not valid XML")
    except OSError:
        raise AuditError(f"{path}: cannot be read")

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


def load_policy(path):
    """Read the YAML policy and return it as a dictionary."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            policy = yaml.safe_load(handle)
    except FileNotFoundError:
        raise AuditError(f"{path}: file not found")
    except (yaml.YAMLError, UnicodeDecodeError):
        raise AuditError(f"{path}: not valid YAML")
    except OSError:
        raise AuditError(f"{path}: cannot be read")

    if policy is None:  # an empty file means no checks at all
        return {}
    if not isinstance(policy, dict):
        raise AuditError(f"{path}: policy must be a mapping")
    return policy


def find_violations(devices, policy):
    """Check every device and return one combined list of violations."""
    violations = []
    for device in devices:
        violations.extend(device.check(policy))
    return violations


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
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
    except OSError:
        raise AuditError(f"{path}: cannot be written")


def main(argv):
    """Run the audit and return the exit code (0 ok, 1 bad file, 2 bad usage)."""
    if len(argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        return 2

    try:
        site, devices, skipped = load_devices(argv[1])
        policy = load_policy(argv[2])
        violations = find_violations(devices, policy)
        report = build_report(site, devices, skipped, violations)
        write_report(report, "audit.json")
    except AuditError as error:
        print(error)
        return 1

    print(f"site: {site}")
    print(f"devices: {len(devices)} kept, {skipped} skipped")
    print(f"violations: {len(violations)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
