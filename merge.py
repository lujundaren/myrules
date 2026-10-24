#!/usr/bin/env python3
"""自用多模块去广告规则聚合脚本 (自动去重与合并)

功能流程：
1. 读取 sources.txt 中的上游去广告模块源列表；
2. 逐一拉取并解析段落（[Rule] / [URL Rewrite] / [Header Rewrite] / [Map Local] / [Script] / [MITM] 等）；
3. 提取并规范化所有段落内容与 MITM 主机名，彻底清除 %APPEND% / %INSERT% 语法修饰符；
4. 记录源与脚本的变更日志至 security-report.txt，不设阻断性限制；
5. 去重并自动合并输出至 dist/merged.sgmodule 与 dist/manifest.json。
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(ROOT, "sources.txt")
OUTPUT = os.path.join(ROOT, "dist", "merged.sgmodule")
MANIFEST = os.path.join(ROOT, "dist", "manifest.json")
BASELINE = os.path.join(ROOT, "baseline.json")
REPORT = os.path.join(ROOT, "security-report.txt")

PREFERRED_ORDER = [
    "Rule",
    "URL Rewrite",
    "Header Rewrite",
    "Map Local",
    "Body Rewrite",
    "Host",
    "Script",
]
HEADER_NAME = "去广告规则增强版"


def fetch(url, retries=2, binary=False):
    """带重试的网络请求获取函数"""
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = r.read()
                return data if binary else data.decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1.0 * (i + 1))
    raise RuntimeError(f"fetch failed after {retries}: {last}")


def sha256(text):
    """计算字符串的 SHA-256 哈希"""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def parse_sections(text):
    """解析模块中的配置段落"""
    sections = OrderedDict()
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[(.+?)\]\s*$", line)
        if m:
            cur = m.group(1).strip()
            sections.setdefault(cur, [])
            continue
        if cur is not None:
            sections[cur].append(line)
    return sections


def extract_script_paths(script_lines):
    """提取 [Script] 段中的远程脚本地址"""
    paths = []
    for ln in script_lines:
        m = re.search(r"script-path\s*=\s*([^,\s]+)", ln)
        if m:
            paths.append(m.group(1).strip())
    return paths


def host_of(url):
    """提取 URL 中的主机名"""
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        return ""


def mitm_hosts_from(lines):
    """提取 [MITM] 段中的主机名列表，并清洗掉修饰符与非法字符"""
    out = []
    for ln in lines:
        if "hostname" not in ln.lower():
            continue
        rhs = ln.split("=", 1)[1] if "=" in ln else ""
        # 清除常见的 Surge 指令修饰符，避免被拼接成错误域名
        rhs = rhs.replace("%APPEND%", "").replace("%INSERT%", "")
        for h in rhs.split(","):
            h = h.strip()
            # 过滤掉空字符串、纯单星号、以及包含非法空格的脏数据
            if h and h != "*" and " " not in h:
                out.append(h)
    return out


def sort_mitm_hosts(hosts):
    """规范化排序 MITM 主机名，确保排除项 (-xxx) 始终排在对应通配符之前"""
    unique_hosts = list(dict.fromkeys(hosts))
    # 将带减号 - 的排除项排在前面，防止被后续通配符覆盖
    negatives = [h for h in unique_hosts if h.startswith("-")]
    positives = [h for h in unique_hosts if not h.startswith("-")]
    return negatives + positives


def sanitize_script_line(ln):
    """对脚本行中未解析的参数模板占位符赋默认安全值，避免运行时 JSON.parse 崩溃"""
    if "{{{" not in ln:
        return ln
    # 移除未指定具体引擎时的占位符（让客户端使用默认系统内核）
    ln = re.sub(r"engine=\{\{\{[^}]+\}\}\},?", "", ln)
    # 针对已知常见模板变量赋予标准有效值，确保内嵌 JSON 合法
    replacements = {
        r"\"lyricLang\":\s*\"\{\{\{[^}]+\}\}\}\"": "\"lyricLang\":\"off\"",
        r"\"captionLang\":\s*\"\{\{\{[^}]+\}\}\}\"": "\"captionLang\":\"off\"",
        r"\"blockUpload\":\s*\{\{\{[^}]+\}\}\}": "\"blockUpload\":true",
        r"\"blockImmersive\":\s*\{\{\{[^}]+\}\}\}": "\"blockImmersive\":true",
        r"\"blockShorts\":\s*\{\{\{[^}]+\}\}\}": "\"blockShorts\":false",
        r"\"debug\":\s*\{\{\{[^}]+\}\}\}": "\"debug\":false",
    }
    for pat, rep in replacements.items():
        ln = re.sub(pat, rep, ln)
    # 通用兜底
    ln = re.sub(r"\"\{\{\{[^}]+\}\}\}\"", "\"\"", ln)
    ln = re.sub(r"\{\{\{[^}]+\}\}\}", "true", ln)
    return ln


def load_baseline():
    """读取安全基线文件"""
    if os.path.exists(BASELINE):
        try:
            with open(BASELINE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:  # noqa: BLE001
            return {}
    return {}


def diff_notes(baseline, source_hashes, script_index):
    """比对上游源与脚本的变更日志"""
    notes = []
    old_src = baseline.get("source_hashes", {})
    for url, h in source_hashes.items():
        if url in old_src and old_src[url] != h:
            notes.append(f"[变更] 上游模块内容已更新: {url}")
        elif url not in old_src:
            notes.append(f"[新增] 新上游模块: {url}")
    old_scripts = baseline.get("scripts", {})
    for url, h in script_index.items():
        if url in old_scripts and old_scripts[url] != h:
            notes.append(f"[变更] 远程脚本内容已更新: {url}")
        elif url not in old_scripts:
            notes.append(f"[新增] 新远程脚本: {url}")
    return notes


def write_report(notes, ok, total):
    """输出合并审计与变更报告文件"""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    lines = [
        "规则合并报告",
        f"时间(UTC): {ts}",
        f"成功拉取源: {ok}/{total}",
        "",
        f"提示/变更: {len(notes)}",
    ]
    lines += [f"  - {n}" for n in notes] or ["  （无）"]
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    # 前置同步：自动拉取最新的 AdGuard 全平台通用规则并刷新精细化模块
    adguard_generator = os.path.join(ROOT, "tools", "generate_adguard_module.py")
    if os.path.exists(adguard_generator):
        try:
            print("正在前置同步 AdGuard 官方全平台规则...")
            import subprocess
            subprocess.run([sys.executable, adguard_generator], check=True, timeout=120)
        except Exception as e:  # noqa: BLE001
            print(f"WARN: AdGuard 前置同步跳过或失败: {e}", file=sys.stderr)

    with open(SOURCES_FILE, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    buckets, seen = OrderedDict(), {}
    mitm_hosts = []
    enable_h2 = False
    source_hashes = {}
    script_urls = []
    ok, failed = 0, []
    def load_one_source(u):
        try:
            if u.startswith(("http://", "https://")):
                t = fetch(u)
            else:
                local_path = os.path.join(ROOT, u) if not os.path.isabs(u) else u
                with open(local_path, encoding="utf-8") as f:
                    t = f.read()
            return u, t, None
        except Exception as e:  # noqa: BLE001
            return u, None, str(e)

    with ThreadPoolExecutor(max_workers=10) as pool:
        fetched_sources = list(pool.map(load_one_source, urls))

    for url, txt, err in fetched_sources:
        if err or txt is None:
            print(f"WARN: 源拉取失败 {url}\n      {err}", file=sys.stderr)
            failed.append(url)
            continue
        ok += 1
        source_hashes[url] = sha256(txt)
        for name, lines in parse_sections(txt).items():
            if name.lower() == "mitm":
                mitm_hosts += mitm_hosts_from(lines)
                if any(re.match(r"^\s*h2\s*=\s*true", l, re.I) for l in lines):
                    enable_h2 = True
                continue
            if name.lower() == "script":
                script_urls += extract_script_paths(lines)
            buckets.setdefault(name, [])
            seen.setdefault(name, set())
            for ln in lines:
                if name.lower() == "script":
                    ln = sanitize_script_line(ln)
                if ln not in seen[name]:
                    seen[name].add(ln)
                    buckets[name].append(ln)

    if ok == 0:
        print("ERROR: 全部源拉取失败，保留旧产物", file=sys.stderr)
        sys.exit(1)

    # 去重与优化 MITM 与 脚本列表
    mitm_hosts = sort_mitm_hosts(mitm_hosts)
    script_urls = list(dict.fromkeys(script_urls))

    # 扫描与记录每个远程脚本哈希
    def load_one_script(su):
        entry = {"url": su, "host": host_of(su)}
        try:
            if "lujundaren/myrules/main/scripts/" in su:
                rel = su.split("lujundaren/myrules/main/")[1]
                local_f = os.path.join(ROOT, rel)
                if os.path.exists(local_f):
                    with open(local_f, encoding="utf-8") as f:
                        body = f.read()
                else:
                    body = fetch(su)
            else:
                body = fetch(su)
            entry["body"] = body
            h = sha256(body)
            return su, entry, h
        except Exception as e:  # noqa: BLE001
            entry["fetch_error"] = str(e)
            return su, entry, None

    with ThreadPoolExecutor(max_workers=10) as pool:
        fetched_scripts = list(pool.map(load_one_script, script_urls))

    scripts = []
    script_index = {}
    for su, entry, h in fetched_scripts:
        scripts.append(entry)
        if h:
            script_index[su] = h

    baseline = load_baseline()
    notes = diff_notes(baseline, source_hashes, script_index)
    write_report(notes, ok, len(urls))

    # ── 生成最终模块产物 ──
    ordered = [s for s in PREFERRED_ORDER if s in buckets]
    ordered += [s for s in buckets if s not in PREFERRED_ORDER]
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    out = [
        f"#!name={HEADER_NAME}",
        f"#!desc=每日自动合并 | 源 {ok} | MITM {len(mitm_hosts)} | 脚本 {len(scripts)} | {ts} UTC",
        "#!category=广告拦截",
        "#!author=lujundaren",
        "",
    ]
    for name in ordered:
        if not buckets[name]:
            continue
        out.append(f"[{name}]")
        out.extend(buckets[name])
        out.append("")
    if mitm_hosts:
        out.append("[MITM]")
        if enable_h2:
            out.append("h2 = true")
        out.append("hostname = %APPEND% " + ", ".join(mitm_hosts))
        out.append("")

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump({
            "generated": ts + " UTC",
            "sources_ok": ok, "sources_total": len(urls),
            "mitm_hosts": mitm_hosts,
            "scripts": [{"url": s["url"], "host": s["host"]} for s in scripts],
        }, f, ensure_ascii=False, indent=2)

    # 刷新基线
    with open(BASELINE, "w", encoding="utf-8") as f:
        json.dump({
            "updated": ts + " UTC",
            "source_hashes": source_hashes,
            "scripts": script_index,
            "mitm_hosts": mitm_hosts,
        }, f, ensure_ascii=False, indent=2)

    print(f"OK: 合并完成！有效源 {ok}/{len(urls)} -> {OUTPUT}")
    print(f"    包含段落: {', '.join(ordered)} | MITM 主机: {len(mitm_hosts)} | 净化脚本: {len(scripts)}")
    if notes:
        print(f"    变更提示: {len(notes)} 条（见 security-report.txt）")
    if failed:
        print(f"    失败源 {len(failed)}: {failed}")


if __name__ == "__main__":
    main()
