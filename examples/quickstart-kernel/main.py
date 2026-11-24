"""Drako v4 Quickstart: Authority Kernel + Operator-Signed Consent + Memory Gate + Receipts.

Run:
    python examples/quickstart-kernel/main.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from drako.kernel import ACS_SPEC_PIN
from drako.kernel.authority import Label, TrustLevel, sign_consent_token
from drako.kernel.envelope import Guardian
from drako.kernel.host import Host, HostConfig
from drako.kernel.receipts import generate_keypair, verify_chain


def main() -> None:
    # Operator keypair (kept off production agent nodes) + Host signing keypair
    op_priv, op_pub = generate_keypair()
    host_priv, host_pub = generate_keypair()

    profile = {
        "spec_pin": ACS_SPEC_PIN,
        "default_effect": "deny",
        "tools": {
            "search_docs": {"id": "rule:search", "effect": "allow"},
            "delete_backup": {
                "id": "rule:delete-backup",
                "effect": "deny",
                "reason": "Destructive action requires operator Ed25519 signature",
                "approval_liftable": True,
            },
        },
    }

    store_path = Path(".drako/quickstart_receipts.jsonl")
    if store_path.exists():
        store_path.unlink()

    host = Host(
        Guardian(profile),
        HostConfig(
            agent_id="quickstart-agent",
            store_path=str(store_path),
            private_pem=host_priv,
            public_pem=host_pub,
            operator_public_pem=op_pub,
        ),
    )

    user_lbl = Label("user:demo", TrustLevel.USER, frozenset({"read", "irreversible"}))

    # 1. Normal read -> PERMIT
    d1, r1 = host.govern_tool_call("search_docs", {"q": "eu ai act art 50"}, [user_lbl], side_effect_class="read")
    print(f"[1] search_docs -> {d1.verdict} (receipt={r1['receipt_id']})")

    # 2. Destructive action without consent -> DENY with anti-TOCTOU approval seam
    args = {"backup_id": "bk-2026-11"}
    d2, r2 = host.govern_tool_call("delete_backup", args, [user_lbl], side_effect_class="irreversible")
    print(f"[2] delete_backup (no consent) -> {d2.verdict} (binds={d2.approval['binds'][:16]}...)")

    # 3. Operator signs ConsentToken offline bound to exact args_hash -> PERMIT
    token = sign_consent_token(
        token_id="ct-demo-1",
        issuer="human:operator",
        action_hash=d2.approval["binds"],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        operator_private_pem=op_priv,
    )
    d3, r3 = host.govern_tool_call(
        "delete_backup", args, [user_lbl], side_effect_class="irreversible", consent_token=token
    )
    print(f"[3] delete_backup (signed consent) -> {d3.verdict} (receipt={r3['receipt_id']})")

    # 4. Memory Firewall (ASI06): block tool-laundered write
    bad_mem, r4 = host.govern_memory_write("long-term", [Label("tool:web", TrustLevel.TOOL, frozenset({"read"}))])
    print(f"[4] memory_write (tool output) -> {bad_mem.verdict}: {bad_mem.reason}")

    # 5. Offline chain verification
    ok, broken_idx = verify_chain([r1, r2, r3, r4], host_pub)
    print(f"[5] Full 4-receipt Ed25519 chain valid: {ok} (broken_idx={broken_idx})")


if __name__ == "__main__":
    main()
