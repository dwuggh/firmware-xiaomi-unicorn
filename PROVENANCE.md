# Firmware provenance

The current payload is the Xiaomi 12S Pro (Unicorn) snapshot verified on
2026-11-13. The full official stock ROM build was not recorded; the snapshot
label identifies the verification date only.

| Component | Input and installed layout |
| --- | --- |
| GPU | Six stock `/vendor/firmware/` files; SQE/GMU under `lib/firmware/qcom/`, split ZAP under `qcom/sm8475/xiaomi/unicorn/` |
| ADSP and SLPI | Split MDT images from `modem_a:image/`; installed under `qcom/sm8475/xiaomi/unicorn/` |
| WLAN | Matching AMSS, M3, BDF and REGDB from `modem_a:image/qca6490/`; installed under `ath11k/WCN6855/hw2.1/` |

[manifest.json](share/unicorn-firmware/manifest.json) records all 61 original
inputs, sizes, SHA256 hashes and source paths. DSP/WLAN byte extents document
historical verification; new extraction resolves FAT directory entries and
cluster chains instead of reusing those offsets.

AMSS is renamed from `amss20.bin` to `amss.bin`. The generated ath11k API2
`board-2.bin` preserves the selected `bd_l2sgf.elf` and `regdb_xiaomi.bin` bytes
in its BOARD and REGDB records. Its PCI/QMI board key is pinned in the manifest.
The selected BDF follows the [MiCode driver source](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/tree/fa4513e61931e11a59e3f177ae590d4e090d7229).

[source.json](share/unicorn-firmware/source.json) identifies the snapshot and
manifest hash. [validation.json](share/unicorn-firmware/validation.json)
records split-MDT structure checks and the generated board-file hash;
[SHA256SUMS](SHA256SUMS) covers all runtime files and these three metadata files.
These checks establish file identity and structure, not secure-world signature
acceptance or compatibility with every handset or kernel.

The payload excludes Bluetooth, Linux regulatory.db, full modem/partition
images, factory MAC addresses and private speaker calibration. Those inputs
are managed separately by the consumer.

Tool source origins and licensing are documented in [tools/README.md](tools/README.md)
and [tools/LICENSE](tools/LICENSE).
