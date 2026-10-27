"""Test persistence layer and repositories."""
import uuid
from m7_core.repository.analysis_repo import AnalysisRepository
from m7_core.repository.action_repo import ActionRepository
from m7_core.repository.audit_repo import AuditRepository


def test_analysis_persistence(db_session):
    repo = AnalysisRepository(db_session)
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    sha = "a" * 64

    model, is_dup = repo.get_or_create(aid, vid, sha)
    assert not is_dup
    assert model.analysis_id == aid
    assert model.pipeline_status == "received"

    # Save section
    sec = repo.save_section(aid, "static", {"status": "done"}, "M2")
    assert sec.written_by == "M2"

    doc = repo.assemble_document(aid)
    assert doc is not None
    assert doc["analysis_id"] == aid
    assert doc["static"] == {"status": "done"}
    assert doc["pipeline"]["status"] == "received"


def test_action_and_audit_persistence(db_session):
    action_repo = ActionRepository(db_session)
    audit_repo = AuditRepository(db_session)
    aid = str(uuid.uuid4())
    act_id = str(uuid.uuid4())

    act = action_repo.save_action(aid, {
        "action_id": act_id,
        "type": "block_hash",
        "target": "c" * 64,
        "mode": "dry_run",
        "status": "proposed",
        "playbook": "trojan_generic",
        "approval": {"required": False}
    })
    assert act.action_id == act_id
    assert act.status == "proposed"

    audit_entry = audit_repo.log(
        actor="M6",
        action_type="propose_action",
        detail={"action_id": act_id},
        analysis_id=aid,
        action_id=act_id
    )
    assert audit_entry.actor == "M6"
    assert audit_entry.action_type == "propose_action"
