from __future__ import annotations

from ci.fleet import repository_expectations


def test_should_enforce_exact_consumer_set_when_central_is_not_main() -> None:
    # Given a pull-request shadow where central main still has legacy protection
    include_central = False

    # When the immutable fleet expectations are selected
    expectations = repository_expectations(include_central)

    # Then exactly the nine migrated consumers require sole Dagger
    assert tuple(item.name for item in expectations) == (
        "agentic-context-service",
        "agentic-saga",
        "almamesh",
        "aml-filter",
        "assay",
        "edge-proc",
        "edge-reco",
        "edgeproc-core",
        "privacy-core",
    )
    assert all(item.required_contexts == ("Dagger",) for item in expectations)
    assert all(item.conversation_resolution for item in expectations)


def test_should_include_central_only_after_main_cutover() -> None:
    # Given an exact-main fleet run after central protection cutover
    include_central = True

    # When the final expectation set is selected
    expectations = repository_expectations(include_central)

    # Then ci joins the same sole app-bound Dagger contract
    assert tuple(item.name for item in expectations)[-1] == "ci"
    assert expectations[-1].linear_history is False
    assert expectations[-1].conversation_resolution is False
