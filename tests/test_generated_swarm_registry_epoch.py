"""Auto-routing must persist the registry epoch fallback will reload."""
from __future__ import annotations

from dataclasses import replace
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

_HERMETIC_DIR = os.path.dirname(os.path.abspath(__file__))
if _HERMETIC_DIR not in sys.path:
    sys.path.insert(0, _HERMETIC_DIR)
import hermetic_env  # noqa: F401

from puppetmaster.model_registry import ModelSpec, save_registry
from puppetmaster.orchestrator import Orchestrator
from puppetmaster.platform_billing import BillingStatus, _BILLING_CACHE
from puppetmaster.routing_authority import load_bound_registry
from puppetmaster.static_catalog import curated_to_specs
from puppetmaster.store import SwarmStore
from puppetmaster.swarm_launch import build_analysis_swarm_specs


def _billing(adapter, **_kwargs):
    billing = "plan" if adapter == "codex" else "api"
    return BillingStatus(
        adapter=adapter,
        billing=billing,
        healthy=adapter in {"codex", "agentic"},
        detail="ready",
        evidence=[],
    )


class GeneratedSwarmRegistryEpochTests(TestCase):
    def setUp(self) -> None:
        _BILLING_CACHE.clear()

    def tearDown(self) -> None:
        _BILLING_CACHE.clear()

    def test_catalog_refresh_persists_the_epoch_fallback_will_reload(self) -> None:
        with TemporaryDirectory() as tmp:
            registry_path = Path(tmp) / "models.json"
            curated = curated_to_specs(
                "agentic", "api", [], allowed_providers={"opencode-go"}
            )
            # Reconciliation refreshes this row without adding a model.
            curated[0] = replace(curated[0], tags=list(reversed(curated[0].tags)))
            save_registry(
                [
                    ModelSpec(
                        id="codex/gpt-5-5",
                        adapter="codex",
                        adapter_model_name="gpt-5.5",
                        capability_score=90,
                        billing="plan",
                    ),
                    ModelSpec(
                        id="agentic/openai/gpt-5-6-sol",
                        adapter="agentic",
                        adapter_model_name="gpt-5.6-sol",
                        capability_score=92,
                        billing="api",
                        payload_defaults={"provider": "openai"},
                    ),
                    *curated,
                ],
                registry_path,
            )
            spec = build_analysis_swarm_specs(
                "read-only canary",
                ["canary"],
                adapter="codex",
                cwd=tmp,
                allowed_model_ids=[
                    "codex/gpt-5-5",
                    "agentic/openai/gpt-5-6-sol",
                ],
            )[0]
            spec = replace(
                spec,
                payload={**spec.payload, "registry_path": str(registry_path)},
            )
            store = SwarmStore(Path(tmp) / ".puppetmaster")
            orchestrator = Orchestrator(store)
            job = store.create_job("registry epoch fallback")
            with patch(
                "puppetmaster.providers.available_providers",
                return_value={"openai", "opencode-go"},
            ), patch(
                "puppetmaster.platform_billing.detect_adapter_billing",
                side_effect=_billing,
            ), patch(
                "puppetmaster.preflight.adapter_cli_present",
                return_value=True,
            ):
                routed, _decisions = orchestrator._apply_auto_routing(job, [spec])

            path, _registry, digest = load_bound_registry(routed[0].payload)
            self.assertEqual(path, registry_path.resolve())
            self.assertEqual(digest, routed[0].payload["registry_digest"])


if __name__ == "__main__":
    import unittest

    unittest.main()
