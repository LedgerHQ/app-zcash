The `application_client` directory contains the minimalist python client for crafting and sending APDUs to the application.
It is extracted in order to be able to be used in both tests setup.

The `standalone` directory contains the standalone tests of the application, when it is started from the Dashboard of the device (main use case).

The `swap` directory contains the tests of the **SWAP** feature of the application, when it is started by the Exchange application through the `os_lib_call` API.
This setup needs the Exchange and Ethereum binaries compiled.

PCZT Orchard spend-authorizing signatures are verified against the action's
randomized verification key and an independently computed transaction digest.
Retained signature vectors must verify too. Byte-for-byte comparison is not
appropriate when an optimization changes how many blinded SDK operations consume
the emulator's deterministic random stream before the randomized signature.
