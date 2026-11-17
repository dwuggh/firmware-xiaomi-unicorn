# firmware-xiaomi-unicorn

小米 12S Pro（Unicorn）的 Linux 运行时固件。
仓库直接提供已整理的二进制文件，可复制到 Linux 固件目录，也可打包为 `.tar.zst`。

## 固件内容

```text
lib/firmware/
  qcom/a730_sqe.fw
  qcom/gmu_gen70000.bin
  qcom/sm8475/xiaomi/unicorn/{a730_zap,adsp,slpi}.*
  ath11k/WCN6855/hw2.1/{amss.bin,m3.bin,regdb.bin,board-2.bin}
share/unicorn-firmware/{manifest.json,source.json,validation.json}
SHA256SUMS
```

共 61 个运行时文件，覆盖 GPU、ADSP、SLPI 和匹配的 WLAN 固件。
`board-2.bin` 包含原厂 BDF 与 REGDB；其余固件保持清单记录的原始字节。
蓝牙与 Linux `regulatory.db` 由消费方另外提供。
本仓库不包含完整基带、分区刷写镜像、设备身份或扬声器私有校准数据。

当前版本为 `snapshot-20261113`，表示历史验证快照；原始资料缺少完整 ROM
版本号，不能将此标签解释为官方 ROM 版本。来源见 [PROVENANCE.md](PROVENANCE.md)。

## 校验与使用

```sh
sha256sum -c SHA256SUMS
python3 tools/firmware.py verify
```

`lib/firmware/` 可作为 Linux 固件包的输入。Nix 消费方可以固定 Git 提交，
或固定 GitHub Release 中 `.tar.zst` 的下载地址和 SHA256。

## 生成 Release 包

```sh
python3 tools/firmware.py release \
  --version snapshot-20261113 \
  --output out/unicorn-firmware-snapshot-20261113.tar.zst

python3 tools/firmware.py verify \
  --archive out/unicorn-firmware-snapshot-20261113.tar.zst
```

直接使用仓库中的二进制生成归档，无需手机或原始 ROM。
包内仅有运行时固件、来源清单、说明与校验和，不包含工具或 Git 元数据。
发布格式固定为 `.tar.zst`；整包信息见 [archive.json](archive.json)。
命令只生成本地文件，不创建 GitHub 仓库或上传 Release。

提取、更新与测试见 [tools/README.md](tools/README.md)。
工具采用 MIT 许可证；固件不适用该许可证，详见 [LICENSE](LICENSE)。
