"""Compile the real SDK I/O sources against a scripted host OS and transport."""
import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--sdk-dir", type=Path, help="Override the SDK source resolved by Cargo")
    args = parser.parse_args()
    sdk_dir = args.sdk_dir
    if sdk_dir is None:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root,
        ))
        sdk, = (package for package in metadata["packages"]
                if package["name"] == "ledger_device_sdk")
        sdk_dir = Path(sdk["manifest_path"]).parent
    with tempfile.TemporaryDirectory(prefix="ledger-io-tests-") as directory:
        work = Path(directory)
        # Preserve the SDK's module tree under mod.rs so #[path] resolves its children.
        shutil.copytree(sdk_dir / "src/io_new", work / "sdk_io")
        shutil.copyfile(sdk_dir / "src/io_new.rs", work / "sdk_io/mod.rs")
        shutil.copyfile(sdk_dir / "src/seph.rs", work / "sdk_seph.rs")
        shutil.copyfile(Path(__file__).with_name("sdk_io.rs"), work / "sdk_io.rs")
        binary = work / "sdk-io-tests"
        subprocess.run(["rustc", "--edition=2024", "--test", str(work / "sdk_io.rs"),
                        "-o", str(binary)], check=True)
        subprocess.run([str(binary), "--test-threads=1"], check=True)
        shutil.copyfile(root / "src/swap/panic_handler.rs", work / "swap_panic_handler.rs")
        shutil.copyfile(Path(__file__).with_name("swap_panic.rs"), work / "swap_panic.rs")
        for failure in (False, True):
            binary = work / "swap-panic"
            command = ["rustc", "--edition=2024", "-C", "panic=abort",
                       str(work / "swap_panic.rs"), "-o", str(binary)]
            if failure:
                command += ["--cfg", "send_failure"]
            subprocess.run(command, check=True)
            subprocess.run([str(binary)], check=True)
            print(f"Swap panic returns to Exchange with send_failure={failure}", flush=True)


if __name__ == "__main__":
    main()
