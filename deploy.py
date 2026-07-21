#!/usr/bin/env python3
"""One-shot deployment wizard for the text-steganography repo.

Asks for your GitHub username, fixes the hardcoded links in README/demo/LICENSE
to point at your live repo, commits + pushes, and enables GitHub Pages on the
/demo folder. Assumes you already ran `gh auth login` once so `gh` has creds.
No tokens are read or stored by this script.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent


def ask(prompt: str) -> str:
    return input(prompt).strip()


def patch_file(path: Path, pattern: str, repl: str) -> bool:
    text = path.read_text(encoding="utf-8")
    new = re.sub(pattern, repl, text)
    if new == text:
        return False
    path.write_text(new, encoding="utf-8")
    return True


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=str(REPO_DIR), text=True, capture_output=True)


def main() -> int:
    print("text-steganography deployment wizard")
    print("------------------------------------")

    username = ask("GitHub username: ")
    if not username or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", username):
        print("error: invalid username")
        return 2

    full_name = ask(f"Name for LICENSE copyright (enter for '{username}'): ") or username

    print(f"\nrewriting links in 3 files to use '{username}'...")

    # README line 5:  https://samsha.github.io/text-steganography/  (lowercase)
    patch_file(REPO_DIR / "README.md",
               r"https://[\w-]+\.github\.io/text-steganography/",
               f"https://{username.lower()}.github.io/text-steganography/")

    # demo/index.html line 235:  https://github.com/Samsha/text-steganography
    patch_file(REPO_DIR / "demo" / "index.html",
               r"https://github\.com/[\w-]+/text-steganography",
               f"https://github.com/{username}/text-steganography")

    # LICENSE line 3:  Copyright (c) 2026 Samsha
    patch_file(REPO_DIR / "LICENSE",
               r"Copyright \(c\) \d+ .*",
               f"Copyright (c) 2026 {full_name}")

    print("committing...")
    r = run(["git", "add", "README.md", "demo/index.html", "LICENSE"])
    if r.returncode != 0:
        print("git add failed:", r.stderr); return 1
    r = run(["git", "commit", "-m", "point demo and repo links at live username"])
    if r.returncode != 0:
        print("git commit failed (maybe nothing to commit?):", r.stderr)

    print("pushing to GitHub...")
    r = run(["git", "push"])
    if r.returncode != 0:
        # gh repo create --push may already exist; check remote
        r2 = run(["git", "remote", "-v"])
        if "origin" not in (r2.stdout + r2.stderr):
            print("no 'origin' remote. Run this first:\n"
                  f"  gh repo create {username}/text-steganography"
                  " --public --source=. --push")
            return 1
        print("push failed:", r.stderr); return 1

    # Use gh api to set Pages branch+path.
    # First POST to enable Pages on the repo; if it already exists, PUT.
    print("enabling GitHub Pages on branch=master, path=/demo ...")
    pages_payload = ["-F", "source[branch]=master", "-F", "source[path]=/demo"]
    r = run([
        "gh", "api",
        f"repos/{username}/text-steganography/pages",
        "-X", "POST", *pages_payload,
    ])
    if r.returncode != 0:
        r = run([
            "gh", "api",
            f"repos/{username}/text-steganography/pages",
            "-X", "PUT", *pages_payload,
        ])
        if r.returncode != 0:
            print("could not enable Pages via api:", r.stderr)
            print("do it in the browser: Settings -> Pages -> "
                  "branch=master, path=/demo -> Save")

    print("\ndone. live URL will be:")
    print(f"  https://{username.lower()}.github.io/text-steganography/")
    print("wait ~60s, then open it. verify CI in repo Actions tab.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
