"""Test cryptographic tamper-evident audit chain."""
from m6_response.audit.audit_chain import AuditChain, AuditEntry


def test_audit_chain_validity():
    chain = AuditChain()
    chain.append(actor="M6", action_type="propose", detail={"action_id": "1"})
    chain.append(actor="analyst", action_type="approve", detail={"action_id": "1"})
    chain.append(actor="M6", action_type="execute", detail={"action_id": "1"})

    assert len(chain.entries) == 3
    assert chain.verify() is True


def test_audit_chain_detects_tampering():
    chain = AuditChain()
    chain.append(actor="M6", action_type="propose", detail={"action_id": "1"})
    chain.append(actor="analyst", action_type="approve", detail={"action_id": "1"})

    # Tamper with entry in place by replacing with modified AuditEntry
    tampered = AuditEntry(
        entry_id=chain.entries[0].entry_id,
        prev_hash=chain.entries[0].prev_hash,
        timestamp=chain.entries[0].timestamp,
        actor="hacker",
        action_type=chain.entries[0].action_type,
        detail=chain.entries[0].detail,
        entry_hash=chain.entries[0].entry_hash
    )
    chain.entries[0] = tampered
    assert chain.verify() is False
