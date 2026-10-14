# Importing the module applies its git-worktree patch; the imported fixture is registered here.
from suite_conftest import deterministic_rng_fixture, supported_devices  # noqa: F401

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)

additional_speculos_arguments = deterministic_rng_fixture("zcash-testnet-tests")
