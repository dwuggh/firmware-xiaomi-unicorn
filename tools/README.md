# Firmware maintenance tools

The public payload is `../lib/firmware/`; these tools reproduce and verify it.
Python 3.11+ and the standard library are required; release packaging also needs
`zstd`. Run commands from the repository root. OpenSSH and phone-side Python 3
are only needed for phone extraction.

## Verify and package committed firmware

```sh
python3 tools/firmware.py verify
python3 tools/firmware.py release \
  --version snapshot-20261113 \
  --output out/unicorn-firmware-snapshot-20261113.tar.zst
python3 tools/firmware.py verify \
  --archive out/unicorn-firmware-snapshot-20261113.tar.zst
```

`verify` checks the exact runtime file set, SHA256SUMS, the pinned OEM hashes,
ath11k BDF/REGDB records and split-MDT structure. `--tree PATH` selects another
checkout. `--output PATH` exports a verified runtime directory.

`release` packages the checked-in files by default. The version must match
`share/unicorn-firmware/source.json`. It selects only runtime files, generates
the package README and checksums, sorts paths and creates USTAR entries with
mode 0644, uid/gid/mtime 0, then compresses with `zstd -T1 -10`.
Identical input and tool versions produce identical bytes. Existing outputs are
never overwritten. Archives and raw inputs stay outside Git in `out/` and `inputs/`.

## Extract from stock sources

Inputs are a raw FAT16 modem image and an unpacked vendor root containing
`firmware/`. OTA, payload, super, EROFS and ext4 unpacking are outside this tool.

```sh
python3 tools/firmware.py extract \
  --modem-image inputs/ROM_VERSION/modem.img \
  --vendor-dir inputs/ROM_VERSION/vendor \
  --source-id 'unicorn:FULL_OFFICIAL_ROM_BUILD' \
  --output out/unicorn/payload
```

For read-only extraction over LAN, replace `--modem-image` with
`--phone root@unicorn --slot a`. Choose the slot explicitly; the phone needs
partition-read permission. GPU files still come from the local vendor root.
No mounting, flashing, installation or reboot is performed.

The fixed manifest requires all 61 original file lengths and hashes to match.
Different ROM bytes require a separately reviewed manifest, followed by hardware
testing. Extraction evidence goes into `extraction-report.json` in the local raw
payload; it does not rewrite the historical snapshot's provenance.

Export a candidate Linux layout from the raw files:

```sh
python3 tools/firmware.py export \
  --input out/unicorn/payload \
  --version snapshot-20261113 \
  --output out/unicorn/linux
```

The candidate directory includes a package-specific README and SHA256SUMS.
When updating the repository, copy only `lib/` and `share/`, then regenerate the
root SHA256SUMS over those files. Keep the repository README separate.
`release --input PATH` can still build an archive directly from a verified raw
payload. A matching current archive is pinned in `archive.json`.

## Tests

```sh
PYTHONPATH=tools python3 -m unittest discover -s tools/tests -v

UNICORN_TEST_INPUT="$PWD/inputs/unicorn-snapshot-20261113" \
  PYTHONPATH=tools python3 -m unittest discover -s tools/tests -v
```

FAT tests use synthetic images. Optional integration tests take local OEM inputs,
construct a fresh FAT allocation, extract and export it, compare two deterministic
archives and reject tampered firmware. Repository tests use the checked-in data.
Tests do not contact a phone.

## Source and license

The tools were developed for Unicorn. `firmware_extractor/fat.py` and its
synthetic tests derive from the local `xiaomi12S-pro-nixos` prototype;
`firmware_extractor/layout.py` derives from the original device repository's
`pkgs/unicorn/assemble-firmware.py`. The firmware manifest was imported unchanged
from that repository. The parser documents its FAT-format reference and limits.

The MIT license in [LICENSE](LICENSE) applies to tool source and tests.
It grants no rights to OEM firmware binaries.
