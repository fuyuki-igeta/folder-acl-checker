# -*- coding: cp932 -*-
"""
フォルダ権限確認ツール
- 探索: 3階層まで・フォルダのみ
- 表示: アカウント名のみ
"""

import subprocess
import os
import sys
import argparse
import locale
import ctypes
from datetime import datetime


def get_accounts(folder_path: str) -> list[dict]:
    """icacls でフォルダの ACL を取得し、アカウント名のみ返す。"""
    icacls_path = _to_extended_path(folder_path)
    if icacls_path != folder_path:
        print(f"  [INFO] long path ({len(folder_path)} chars): using extended path", file=sys.stderr)
    try:
        result = subprocess.run(
            ["icacls", icacls_path],
            capture_output=True,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
        )
    except FileNotFoundError:
        print("[ERROR] icacls が見つかりません。Windows 環境で実行してください。", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        print(f"[WARN] icacls 失敗 (code={result.returncode}): {result.stderr.strip()}", file=sys.stderr)

    records = []
    seen = set()
    parse_error = False
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or "正常に処理" in line or "Successfully" in line:
            continue
        # icacls は最初の ACE 行にパスを先頭に付ける - 除去する
        for _pfx in (icacls_path, folder_path):
            if os.path.normcase(line).startswith(os.path.normcase(_pfx)):
                line = line[len(_pfx):].strip()
                break
        if ":" in line:
            account = line.split(":", 1)[0].strip()
            if len(account) == 1 and account.isalpha() and line.split(':', 1)[1].startswith('\\'):
                parse_error = True
                continue
            if account and account not in seen:
                seen.add(account)
                records.append({
                    "フォルダパス": folder_path,
                    "アカウント": account,
                })
    if result.returncode != 0 and not records:
        records.append({
            "フォルダパス": folder_path,
            "アカウント": "[ICACLS_ERROR]",
        })
    if parse_error:
        records.insert(0, {
            "フォルダパス": folder_path,
            "アカウント": "[PARSE_ERROR] CP932 decode failed",
        })
    return records


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _to_extended_path(path: str) -> str:
    if len(path) < 260 or path.startswith('\\\\?\\'):
        return path
    if path.startswith('\\\\'):
        return '\\\\?\\UNC\\' + path[2:]
    return '\\\\?\\' + path



def _is_reparse_point(path: str) -> bool:
    """Detect junction/symlink via FILE_ATTRIBUTE_REPARSE_POINT (0x400).
    os.path.islink() may miss junctions on some Windows environments.
    """
    try:
        st = os.lstat(path)
        return bool(getattr(st, 'st_file_attributes', 0) & 0x400)
    except OSError:
        return False


def _is_hidden(path: str) -> bool:
    try:
        st = os.lstat(path)
        return bool(getattr(st, 'st_file_attributes', 0) & 0x2)
    except OSError:
        return False


def walk_folders(root: str) -> list[str]:
    root = os.path.normpath(root)
    if _is_reparse_point(root):
        print(f"[WARN] root is a junction/symlink: {root}", file=sys.stderr)
        return []
    folders = [root]
    for dirpath, dirnames, _ in os.walk(
            root, onerror=lambda e: print(f"  [WARN] access denied: {e.filename}", file=sys.stderr)):
        links = [d for d in dirnames if _is_reparse_point(os.path.join(dirpath, d))]
        for d in links:
            dirnames.remove(d)
            print(f"  [SKIP] junction/symlink: {os.path.join(dirpath, d)}", file=sys.stderr)
        for d in dirnames:
            folders.append(os.path.join(dirpath, d))

    return folders


def export_csv(records: list[dict], output_path: str):
    import csv
    headers = ["フォルダパス", "アカウント"]
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(records)


def main():
    if os.name != "nt":
        print("[ERROR] このツールは Windows 専用です。", file=sys.stderr)
        sys.exit(1)

    if not _is_admin():
        print("[WARN] 管理者権限なしで実行しています。アクセス拒否されたフォルダの権限は取得できません。", file=sys.stderr)

    parser = argparse.ArgumentParser(
        description="フォルダ権限確認ツール ― アカウント名のみ表示",
        
    )
    parser.add_argument("path", help="確認対象のルートフォルダパス")
    parser.add_argument("--output", default="", help="出力CSVファイル名（省略時は自動生成）")
    args = parser.parse_args()

    root = args.path
    if not os.path.isdir(root):
        print(f"[ERROR] フォルダが見つかりません: {root}", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or f"acl_report_{timestamp}.csv"

    print(f"[INFO] 対象フォルダ: {root}")

    folders = walk_folders(root)
    print(f"[INFO] 対象フォルダ数: {len(folders)}")

    all_records = []
    for i, folder in enumerate(folders, 1):
        print(f"  [{i}/{len(folders)}] {folder}")
        all_records.extend(get_accounts(folder))

    if not all_records:
        print("[WARN] 権限情報を取得できませんでした。")
        sys.exit(0)

    if args.output and not os.path.isdir(os.path.dirname(os.path.abspath(args.output))):
        fallback = os.path.join(os.path.expanduser("~"), os.path.basename(output_path))
        print(f"[WARN] 指定したパスが存在しません: {output_path}", file=sys.stderr)
        print(f"[WARN] ホームフォルダに保存します: {fallback}", file=sys.stderr)
        output_path = fallback
    try:
        export_csv(all_records, output_path)
    except PermissionError:
        output_path = os.path.join(os.path.expanduser("~"), os.path.basename(output_path))
        print(f"[WARN] 書き込み権限なし。{output_path} に出力します", file=sys.stderr)
        export_csv(all_records, output_path)
    print(f"\n[完了] {output_path} に出力しました（{len(all_records)} 行）")


if __name__ == "__main__":
    main()
