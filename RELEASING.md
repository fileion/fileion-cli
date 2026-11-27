# Releasing

Do not add Windows or macOS runners; Windows tests run on the VM.

CI (`build.yml`) runs on Ubuntu only, on a `v*` tag or by hand.

## Before tagging: test on the Windows VM

```bash
ssh fileion-winvm hostname            # if it does not answer, the owner restarts the VM
git archive --format=tar -o /tmp/cli.tar HEAD && scp /tmp/cli.tar fileion-winvm:C:/ftest/cli.tar
ssh fileion-winvm "powershell -NoProfile -Command \"Remove-Item -Recurse -Force C:\\ftest\\cli -ErrorAction SilentlyContinue; New-Item -ItemType Directory C:\\ftest\\cli | Out-Null; tar -xf C:\\ftest\\cli.tar -C C:\\ftest\\cli; Set-Location C:\\ftest\\cli; go vet ./...; go test ./...; go build -o C:\\ftest\\fileion.exe .; C:\\ftest\\fileion.exe version\""
rm /tmp/cli.tar
```

Needs Go on the VM. Then tag `vX.Y.Z`; check the release `SHA256SUMS`.
