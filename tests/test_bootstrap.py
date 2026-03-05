from privacy_intent.bootstrap import init_workspace


def test_init_workspace_creates_starter_files(tmp_path) -> None:
    result = init_workspace(tmp_path)
    created_names = sorted(path.name for path in result["created"])
    assert "privacyintent.yaml" in created_names
    assert "privacy_baseline.yaml" in created_names
    assert ".gitkeep" in created_names
