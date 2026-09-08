import os
import subprocess
from pathlib import Path

base = Path(__file__).parent.resolve() / ".test_dependencies"

APP_EXCHANGE_URL = "git@github.com:LedgerHQ/app-exchange.git"
APP_EXCHANGE_DIR = base / "main/app-exchange/"
APP_EXCHANGE_CLONE_DIR = base / "app-exchange/"

APP_ETHEREUM_URL = "git@github.com:LedgerHQ/app-ethereum.git"
APP_ETHEREUM_DIR = base / "libraries/app-ethereum/"
APP_ETHEREUM_CLONE_DIR = base / "app-ethereum/"

DEVICES_CONF = {
    "nanos+": {
        "sdk": "NANOSP_SDK",
        "bin_path": "build/nanos2/bin/",
    },
    "nanox": {
        "sdk": "NANOX_SDK",
        "bin_path": "build/nanox/bin/",
    },
    "stax": {
        "sdk": "STAX_SDK",
        "bin_path": "build/stax/bin/",
    },
    "flex": {
        "sdk": "FLEX_SDK",
        "bin_path": "build/flex/bin/",
    },
    "apex_p": {
        "sdk": "APEX_P_SDK",
        "bin_path": "build/apex_p/bin/",
    },
}


def run_cmd(cmd: str, cwd: Path = Path("."), print_output: bool = False, no_throw: bool = False) -> str:

    print(f"[run_cmd] Running: '{cmd}'' inside '{cwd}'")

    ret = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=cwd,
    )
    if no_throw is False and ret.returncode:
        print(f"[run_cmd] Error {ret.returncode} raised while running cmd: {cmd}")
        print("[run_cmd] Output was:")
        print(ret.stdout)
        raise ValueError()

    if print_output:
        print(f"[run_cmd] Output:\n{ret.stdout}")

    return ret.stdout.strip()


def clone_or_pull(repo_url: str, clone_dir: str):
    # Only needed when cloning / pulling, not when building.
    # By putting the import here we allow the script to be imported inside the docker image
    from git import Repo

    git_dir = os.path.join(clone_dir, ".git")
    if not os.path.exists(git_dir):
        print(f"Cloning into {clone_dir}")
        run_cmd(f"rm -rf {clone_dir}")
        Repo.clone_from(repo_url, clone_dir, recursive=True)
    else:
        print(f"Pulling latest changes in {clone_dir}")
        repo = Repo(clone_dir)
        origin = repo.remotes.origin
        origin.fetch()
        repo.git.reset("--hard", "origin/develop")

        # Update submodules
        print(f"Updating submodules in {clone_dir}")
        run_cmd("git submodule sync", cwd=Path(clone_dir))
        run_cmd("git submodule update --init --recursive", cwd=Path(clone_dir))


def build_app(clone_dir: str, flags: str):
    cmd = "make clean"
    run_cmd(cmd, cwd=Path(clone_dir))
    for d in DEVICES_CONF.values():
        sdk = d["sdk"]
        cmd = f"make -j BOLOS_SDK=${sdk} {flags}"
        run_cmd(cmd, cwd=Path(clone_dir))


def copy_build_output(clone_dir: str, dest_dir: str):
    run_cmd(f"mkdir -p {dest_dir}")
    run_cmd(f"cp -rT {clone_dir}/build {dest_dir}/build")


def use_case_flags(clone_dir: Path, use_case: str) -> str:
    """Resolve a use case declared in `ledger_app.toml` into the make flags it stands for.

    The dependency owns the flags its use case expands to, and they move — reproducing them here
    is how a local build silently drifts away from the one CI runs. Only the use case *name* is
    stated on this side, matching what the root `ledger_app.toml` asks CI to build.
    """
    # Kept local: the module is imported on the host, where the standard library may predate tomllib.
    import tomllib

    manifest = clone_dir / "ledger_app.toml"
    with manifest.open("rb") as f:
        use_cases = tomllib.load(f).get("use_cases", {})

    if use_case not in use_cases:
        raise ValueError(f"{manifest} declares no use case '{use_case}' (has: {', '.join(sorted(use_cases))})")

    return use_cases[use_case]


# ==== Build app-exchange ====
def clone_and_pull_exchange():
    clone_or_pull(APP_EXCHANGE_URL, APP_EXCHANGE_CLONE_DIR)


def build_and_copy_exchange():
    # Without the test public key, Exchange refuses the test signing authority the swap client
    # uses and every scenario dies on SIGN_VERIFICATION_FAIL (0x9D1A).
    build_app(APP_EXCHANGE_CLONE_DIR, flags=use_case_flags(APP_EXCHANGE_CLONE_DIR, "dbg_use_test_keys"))
    copy_build_output(APP_EXCHANGE_CLONE_DIR, APP_EXCHANGE_DIR)


# ==== Build app-ethereum ====
def clone_and_pull_ethereum():
    clone_or_pull(APP_ETHEREUM_URL, APP_ETHEREUM_CLONE_DIR)


def build_and_copy_ethereum():
    build_app(
        APP_ETHEREUM_CLONE_DIR,
        flags=f"COIN=ethereum CHAIN=ethereum {use_case_flags(APP_ETHEREUM_CLONE_DIR, 'use_test_keys')}",
    )
    copy_build_output(APP_ETHEREUM_CLONE_DIR, APP_ETHEREUM_DIR)
