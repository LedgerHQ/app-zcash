import tomllib
from pathlib import Path
from typing import List

import pytest
from ragger.conftest import configuration

# ---------------------------------------------------------------------------
# Git-worktree compatibility patch
#
# Ragger's find_project_root_dir() looks for a .git *directory* to locate the
# project root.  Git worktrees expose a .git *file* (containing a gitdir
# pointer), which is_dir() returns False for, so the lookup walks all the way
# to / and raises ValueError.
#
# Patch the function to accept .git as either a file or a directory.
# ---------------------------------------------------------------------------
import ragger.utils.misc as _ragger_misc


def _find_project_root_dir_worktree_aware(origin: Path) -> Path:
    candidate = origin.resolve()
    while candidate != candidate.parent:
        git_path = candidate / ".git"
        if git_path.exists():  # True for both file (worktree) and directory
            return candidate
        candidate = candidate.parent
    raise ValueError("Could not find project top directory")


_ragger_misc.find_project_root_dir = _find_project_root_dir_worktree_aware

# Also patch the already-imported reference inside base_conftest so that
# prepare_speculos_args and supported_devices pick up the new implementation.
import ragger.conftest.base_conftest as _ragger_base
_ragger_base.find_project_root_dir = _find_project_root_dir_worktree_aware

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)


def _find_project_root() -> Path:
    """Walk up from this conftest to locate the project root (ledger_app.toml)."""
    here = Path(__file__).resolve().parent
    for candidate in [here, here.parent, here.parent.parent]:
        if (candidate / "ledger_app.toml").exists():
            return candidate
    raise FileNotFoundError("ledger_app.toml not found in ancestor directories")


@pytest.fixture(scope="session")
def supported_devices() -> List[str]:
    """Override ragger's default fixture to handle git-worktree layouts.

    Ragger's upstream implementation calls find_project_root_dir() which
    looks for a .git *directory*; git worktrees expose a .git *file*, so
    the lookup fails.  This override reads ledger_app.toml directly.
    """
    with open(_find_project_root() / "ledger_app.toml", "rb") as f:
        manifest = tomllib.load(f)
    devices: List[str] = manifest["app"]["devices"]
    return ["nanosp" if d == "nanos+" else d for d in devices]


@pytest.fixture(scope=configuration.OPTIONAL.BACKEND_SCOPE)
def additional_speculos_arguments():
    return ["--deterministic-rng", "zcash-standalone-tests"]


# Notes :
# 1. Remove this fixture once the pending review screen is removed from the app
# 2. This fixture clears the pending review screen before each test
# 3. The scope should be the same as the one configured by BACKEND_SCOPE in
# ragger/conftest/configuration.py
# @pytest.fixture(scope="class", autouse=True)
# def clear_pending_review(firmware, navigator):
#     # Press a button to clear the pending review
#     if firmware.device.startswith("nano"):
#         print("Clearing pending review")
#         instructions = [
#             NavInsID.BOTH_CLICK,
#         ]
#         navigator.navigate(instructions,screen_change_before_first_instruction=False)
