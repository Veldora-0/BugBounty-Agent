"""Bounded, passive Subfinder integration for the asset-intelligence CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from framework.common.config import ensure_private_directory, write_private_text_file
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.scope.normalizer import is_dns_label_descendant, normalize_hostname, NormalizationError


MAX_RUNTIME_SECONDS = 75
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
MAX_OUTPUT_LINE_BYTES = 16 * 1024
MAX_RESULTS = 1000


def build_subfinder_command(binary: str, root_domain: str, output_path: str, config_path: str) -> List[str]:
    """Build a fixed, passive-only CLI invocation with explicit resource limits."""
    return [
        binary,
        "-domain", root_domain,
        "-json",
        "-collect-sources",
        "-rate-limit", "2",
        "-timeout", "8",
        "-max-time", "1",
        "-t", "1",
        "-disable-update-check",
        "-no-color",
        "-config", config_path,
        "-output", output_path,
    ]


def run_subfinder(root_domain: str, scope_engine: Optional[ScopeEngine]) -> List[Dict[str, Any]]:
    """Enumerate one authorized root passively and return validated, attributed hosts."""
    if scope_engine is None:
        raise ValueError("Subfinder requires an explicit ScopeEngine")
    try:
        root = normalize_hostname(root_domain)
    except NormalizationError as exc:
        raise ValueError("Invalid Subfinder root domain") from exc
    if scope_engine.check(root).status != ScopeStatus.IN_SCOPE:
        raise ValueError("Subfinder root domain is outside the configured scope")
    binary = shutil.which("subfinder")
    if not binary:
        raise FileNotFoundError("Subfinder is not installed; install it with bb-install subfinder")

    directory = tempfile.mkdtemp(prefix="bb-subfinder-")
    try:
        ensure_private_directory(directory)
        output_path = os.path.join(directory, "results.jsonl")
        config_path = os.path.join(directory, "config.yaml")
        write_private_text_file(output_path, "")
        write_private_text_file(config_path, "{}\n")
        command = build_subfinder_command(binary, root, output_path, config_path)
        env = dict(os.environ)
        env.pop("SUBFINDER_CONFIG", None)
        result = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=MAX_RUNTIME_SECONDS,
            env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Subfinder exited with status {result.returncode}")
        if os.path.islink(output_path) or not os.path.isfile(output_path):
            raise ValueError("Subfinder output is missing or is not a regular file")
        os.chmod(output_path, 0o600)
        if os.path.getsize(output_path) > MAX_OUTPUT_BYTES:
            raise ValueError("Subfinder output exceeded the fixed 5 MiB limit")

        candidates: Dict[str, Dict[str, Any]] = {}
        with open(output_path, "rb") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                if line_number > MAX_RESULTS * 2:
                    raise ValueError("Subfinder output exceeded the fixed result-line limit")
                if len(raw_line) > MAX_OUTPUT_LINE_BYTES:
                    continue
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="strict"))
                except (UnicodeError, json.JSONDecodeError):
                    continue
                if isinstance(record, str):
                    hostname_raw, raw_sources = record, []
                elif isinstance(record, dict):
                    hostname_raw = record.get("host") or record.get("hostname") or ""
                    raw_sources = record.get("sources") or record.get("source") or []
                else:
                    continue
                if not isinstance(hostname_raw, str):
                    continue
                try:
                    hostname = normalize_hostname(hostname_raw)
                except NormalizationError:
                    continue
                if hostname == root or not is_dns_label_descendant(hostname, root):
                    continue
                if scope_engine.check(hostname).status != ScopeStatus.IN_SCOPE:
                    continue
                if isinstance(raw_sources, str):
                    sources = [raw_sources]
                elif isinstance(raw_sources, list):
                    sources = [str(source) for source in raw_sources if isinstance(source, (str, int))]
                else:
                    sources = []
                normalized_sources = sorted({source.strip()[:80] for source in sources if source.strip()})[:20]
                candidates[hostname] = {"hostname": hostname, "sources": normalized_sources}
                if len(candidates) >= MAX_RESULTS:
                    break
        return sorted(
            candidates.values(),
            key=lambda item: (item["hostname"].count("."), item["hostname"]),
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Subfinder exceeded its fixed 75-second runtime limit") from exc
    finally:
        shutil.rmtree(directory, ignore_errors=True)
