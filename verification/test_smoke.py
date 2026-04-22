from odb_autodba.agents.planner_agent import PlannerAgent
from odb_autodba.db.investigation_sql import validate_investigation_sql
from odb_autodba.utils.sql_analysis import extract_sql_id


def test_sql_validation_accepts_select():
    assert validate_investigation_sql("select * from dual").ok


def test_sql_validation_rejects_alter():
    assert not validate_investigation_sql("alter system kill session '1,2' immediate").ok


def test_planner_constructs():
    assert PlannerAgent() is not None


def test_extract_sql_id():
    assert extract_sql_id("Analyze SQL_ID abc123def45") == "abc123def45"
