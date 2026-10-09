"""Fetch one pinned upstream Web Vault and verify its release checksum."""

import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

VERSION = "v2026.7.0"
ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".secrets" / "web-release"
NAME = f"bw_web_{VERSION}.tar.gz"
CACHE.mkdir(parents=True, exist_ok=True)
archive = CACHE / NAME
if not archive.exists():
    subprocess.run(
        [
            "gh",
            "release",
            "download",
            VERSION,
            "--repo",
            "dani-garcia/bw_web_builds",
            "--pattern",
            NAME,
            "--pattern",
            "sha256sums.txt",
            "--dir",
            str(CACHE),
        ],
        check=True,
    )
checksums = dict(
    line.split()[::-1]
    for line in (CACHE / "sha256sums.txt").read_text().splitlines()
    if line.strip()
)
expected = checksums.get(NAME) or checksums.get("*" + NAME)
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
if expected != actual:
    raise SystemExit("Web Vault checksum mismatch")
with tarfile.open(archive) as tar:
    tar.extractall(ROOT, filter="data")
if not (ROOT / "web-vault" / "index.html").exists():
    raise SystemExit("Unexpected release layout")
css = ROOT / "web-vault" / "css"
css.mkdir(exist_ok=True)
(css / "vaultwarden.css").write_text((ROOT / "web-vault.css").read_text())
(ROOT / "web-vault" / "vaultwarden-sso.js").write_text(
    (ROOT / "web-vault-sso.js").read_text()
)
(ROOT / "web-vault" / ".assetsignore").write_text("**/*.map\n")
# SSO manages identity externally; this screen only initializes encrypted vault keys.
for language, overrides in {
    "zh_CN": {
        "joinOrganization": "设置保险库主密码",
        "finishJoiningThisOrganizationBySettingAMasterPassword": "主密码用于加密和解锁保险库。身份由北极小站管理。",
        "createAccount": "初始化保险库",
        "accountSuccessfullyCreated": "加密保险库已就绪",
        "inviteAccepted": "主密码设置成功",
    },
    "en": {
        "joinOrganization": "Set your vault master password",
        "finishJoiningThisOrganizationBySettingAMasterPassword": "Your master password encrypts and unlocks the vault. North Station manages your identity.",
        "createAccount": "Initialize vault",
        "accountSuccessfullyCreated": "Your encrypted vault is ready",
        "inviteAccepted": "Master password configured",
    },
}.items():
    messages_file = ROOT / "web-vault" / "locales" / language / "messages.json"
    messages = json.loads(messages_file.read_text())
    for key, message in overrides.items():
        if key not in messages:
            raise SystemExit(f"Missing Web Vault translation: {key}")
        messages[key]["message"] = message
    messages_file.write_text(json.dumps(messages, ensure_ascii=False))

index = ROOT / "web-vault" / "index.html"
index.write_text(
    index.read_text().replace(
        "</head>", '<script src="vaultwarden-sso.js"></script></head>'
    )
)
(ROOT / "web-vault-release.json").write_text(
    json.dumps(
        {
            "version": VERSION,
            "archive": NAME,
            "sha256": actual,
            "source": f"https://github.com/dani-garcia/bw_web_builds/releases/tag/{VERSION}",
        },
        indent=2,
    )
    + "\n"
)
print(f"Verified Web Vault {VERSION}: {actual}")
