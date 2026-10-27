import hashlib
import json
import uuid
import pytest
from m1_ingestion.vault import MAX_FILE_SIZE, SampleVault
import contract.tools.check_module as cm
import contract.tools.validate as v


@pytest.fixture
def temp_vault(tmp_path):
    return SampleVault(storage_dir=tmp_path / "vault")


def test_vault_ingest_and_retrieve_roundtrip(temp_vault):
    original_bytes = b"MZ\x90\x00HelloMalwareAnalysisPlatform"
    sample_rec, event_rec, is_dup = temp_vault.ingest(
        data=original_bytes,
        original_name="trojan.exe",
        submitter="analyst1"
    )

    assert is_dup is False
    assert sample_rec["stored_defanged"] is True
    assert sample_rec["stored_encrypted"] is True
    assert sample_rec["sha256"] == hashlib.sha256(original_bytes).hexdigest()
    assert sample_rec["md5"] == hashlib.md5(original_bytes).hexdigest()
    assert sample_rec["file_type"] == "pe"

    # Verify event structure
    assert event_rec["type"] == "sample.received"
    assert event_rec["producer"] == "M1"
    assert event_rec["payload"]["sha256"] == sample_rec["sha256"]
    assert event_rec["payload"]["file_type"] == "pe"

    # Decryption roundtrip
    retrieved = temp_vault.retrieve(sample_rec["vault_id"])
    assert retrieved == original_bytes


def test_vault_duplicate_detection(temp_vault):
    sample_data = b"MZ\x90\x00IdenticalSampleData12345"
    s1, e1, is_dup1 = temp_vault.ingest(sample_data, "sample1.exe")
    assert is_dup1 is False
    assert "duplicate_of" not in s1

    s2, e2, is_dup2 = temp_vault.ingest(sample_data, "sample2.exe")
    assert is_dup2 is True
    assert s2["vault_id"] == s1["vault_id"]
    assert s2["duplicate_of"] == s1["vault_id"]
    assert e2["payload"]["duplicate"] is True


def test_vault_rejects_empty_file(temp_vault):
    with pytest.raises(ValueError, match="at least 1 byte"):
        temp_vault.ingest(b"", "empty.bin")


def test_vault_rejects_oversized_file(temp_vault):
    # Test checking size bound
    oversized = b"A" * (MAX_FILE_SIZE + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed cap"):
        temp_vault.ingest(oversized, "big.bin")


def test_vault_contract_schema_compliance(temp_vault):
    sample_data = b"MZ\x90\x00ContractValidSample"
    sample_rec, event_rec, _ = temp_vault.ingest(sample_data, "valid.exe")

    # Validate output section against contract gate
    output_doc = {"sample": sample_rec}
    out_errs = cm.check_output("M1", output_doc)
    assert not out_errs, f"Sample section contract violations: {out_errs}"

    # Validate event against contract gate
    ev_errs = cm.check_event("M1", event_rec)
    assert not ev_errs, f"Event contract violations: {ev_errs}"

