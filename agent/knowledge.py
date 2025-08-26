from __future__ import annotations
"""Load and apply external knowledge dictionaries (ports, modules, suid programs)."""
from pathlib import Path
import yaml
from typing import Dict, Any
import ipaddress

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"
_CACHE: Dict[str, Any] = {}

def _load_yaml(name: str) -> dict:
    if name in _CACHE:
        return _CACHE[name]
    path = KNOWLEDGE_DIR / name
    if not path.exists():
        _CACHE[name] = {}
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        data = {}
    _CACHE[name] = data
    return data

def enrich_finding(finding, scanner: str, distro: str):
    # Network ports
    # Normalize network port field name
    if scanner.lower() == "network":
        if 'port' not in finding.metadata and finding.metadata.get('lport'):
            try:
                finding.metadata['port'] = int(finding.metadata.get('lport')) if str(finding.metadata.get('lport')).isdigit() else finding.metadata.get('lport')
            except Exception:
                finding.metadata['port'] = finding.metadata.get('lport')
    if scanner.lower() == "network" and finding.metadata.get("port"):
        ports = _load_yaml("ports.yaml").get("ports", {})
        port_key = str(finding.metadata.get("port"))
        info = ports.get(port_key)
        if info:
            tags = info.get("tags", [])
            for t in tags:
                if t not in finding.tags:
                    finding.tags.append(t)
            finding.metadata.setdefault("service_name", info.get("service"))
            finding.metadata.setdefault("privilege_implication", info.get("privilege_implication"))
    # Kernel / modules
    if scanner.lower() in {"modules","kernel_modules"} and finding.metadata.get("module"):
        modules = _load_yaml("modules.yaml").get("modules", {})
        mod = finding.metadata.get("module")
        info = modules.get(mod)
        if info:
            for t in info.get("tags", []):
                if t not in finding.tags:
                    finding.tags.append(t)
            finding.metadata.setdefault("module_family", info.get("family"))
    # SUID
    if scanner.lower() == "suid" and finding.metadata.get("path"):
        suid = _load_yaml("suid_programs.yaml").get("distro_defaults", {})
        distro_map = suid.get(distro, suid.get("generic", {}))
        expected = set(distro_map.get("expected", []))
        unexpected_tag_list = distro_map.get("unexpected_tags", ["suid_unexpected"])
        import os
        base = os.path.basename(finding.metadata.get("path"))
        if base not in expected:
            for t in unexpected_tag_list:
                if t not in finding.tags:
                    finding.tags.append(t)
            finding.metadata.setdefault("suid_expected", False)
        else:
            finding.metadata.setdefault("suid_expected", True)
    # Org attribution for network connections (ESTABLISHED or LISTEN with rip)
    if scanner.lower() == "network":
        rip = finding.metadata.get("rip")
        if rip and rip != "0.0.0.0":
            orgs = _load_yaml("orgs.yaml").get("orgs", {})
            try:
                ip_obj = ipaddress.ip_address(rip)
            except Exception:
                ip_obj = None
            if ip_obj:
                for name, info in orgs.items():
                    for cidr in info.get("cidrs", []):
                        try:
                            net = ipaddress.ip_network(cidr, strict=False)
                        except Exception:
                            continue
                        if ip_obj in net:
                            # apply tags
                            for t in info.get("tags", []):
                                if t not in finding.tags:
                                    finding.tags.append(t)
                            finding.metadata.setdefault("remote_org", name)
                            break
                    if finding.metadata.get("remote_org"):
                        break

def apply_external_knowledge(state):
    if not state.report:
        return state
    # Attempt distro detection (placeholder: from meta or host_id pattern)
    distro = getattr(state.report.meta, 'distro', None) or 'generic'
    for sr in state.report.results:
        for f in sr.findings:
            enrich_finding(f, sr.scanner, distro)
    return state