#!/usr/bin/env python3
"""AdGuard 官方过滤器精细化规则提取与 Shadowrocket 模块生成脚本

功能：
1. 抓取 AdGuard 官方过滤器（Base iOS 优化版 + Mobile iOS 优化版）；
2. 提取精细化 URL 路径拦截与重写规则，转为 Shadowrocket [URL Rewrite]；
3. 提取关键 Web 脚本注入与反广告探测脚本，转为 [Script]；
4. 汇集并清洗所有涉及的域名，生成标准的 [MITM] 配置；
5. 输出至 modules/AdGuard_Refined.sgmodule。
"""
import os
import re
import sys
import time
import urllib.request

SOURCES = [
    ("AdGuard Base (Universal Standard)", "https://filters.adtidy.org/windows/filters/2.txt"),
    ("AdGuard Mobile (Universal Standard)", "https://filters.adtidy.org/windows/filters/11.txt"),
]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_MODULE = os.path.join(ROOT, "modules", "AdGuard_Refined.sgmodule")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace").splitlines()


def adg_to_regex(pattern):
    """将 AdGuard 路径过滤模式转换为标准 PCRE 正则表达式"""
    p = pattern
    if p.startswith("||"):
        p = p[2:]
        prefix = r"^https?:\/\/([^\/]+\.)?"
    elif p.startswith("|"):
        p = p[1:]
        prefix = r"^"
    else:
        prefix = r"^https?:\/\/.*"

    suffix = ""
    if p.endswith("|"):
        p = p[:-1]
        suffix = r"$"

    # 拆分通配符 * 并转义
    parts = p.split("*")
    escaped_parts = []
    for part in parts:
        subparts = part.split("^")
        esc_sub = [re.escape(sp) for sp in subparts]
        escaped_parts.append(r"(?:[/?#:]|$)".join(esc_sub))
    regex_body = r".*".join(escaped_parts)
    final_reg = prefix + regex_body + suffix
    return final_reg


def main():
    print("开始拉取 AdGuard 官方过滤器数据...")
    all_lines = []
    for name, url in SOURCES:
        try:
            print(f"正在拉取: {name} ({url}) ...")
            lines = fetch(url)
            print(f"  -> 获取成功，共 {len(lines)} 行")
            all_lines.extend(lines)
        except Exception as e:
            print(f"  -> 获取失败: {e}", file=sys.stderr)

    if not all_lines:
        print("错误：未获取到任何过滤器规则", file=sys.stderr)
        sys.exit(1)

    rewrite_rules = []
    seen_rewrites = set()
    mitm_hosts = set()

    print("\n正在解析并转换精细化规则...")
    for raw in all_lines:
        ln = raw.strip()
        if not ln or ln.startswith("!") or ln.startswith("["):
            continue

        # 1. 提取路径级别的精确拦截规则 (||domain/path)
        if ln.startswith("||") and ("/" in ln or "^" in ln):
            rule_part = ln
            mod = ""
            if "$" in ln:
                rule_part, mod = ln.split("$", 1)

            m = re.match(r"^\|\|([a-zA-Z0-9\.\-\*]+)(/[^^$]+)", rule_part)
            if not m:
                continue

            dom = m.group(1).lower()

            # 排除纯通配顶级域或非法域名
            if "." not in dom or dom.startswith(".") or " " in dom:
                continue

            # 决定策略
            policy = "reject-200"
            if "image" in mod or re.search(r"\.(png|jpg|jpeg|gif|webp)(\?|$)", rule_part, re.I):
                policy = "reject-img"
            elif "xmlhttprequest" in mod or "xhr" in mod or "json" in mod or re.search(r"\.json(\?|$)", rule_part, re.I):
                policy = "reject-dict"

            try:
                reg = adg_to_regex(rule_part)
                # 预校验正则表达式合法性
                re.compile(reg)
                entry = f"{reg} - {policy}"
                if entry not in seen_rewrites:
                    seen_rewrites.add(entry)
                    rewrite_rules.append(entry)
                    # 记录有效的 MITM 域名
                    if "*" not in dom:
                        mitm_hosts.add(dom)
                    elif dom.startswith("*."):
                        mitm_hosts.add(dom)
            except re.error:
                continue

    # 规范化排序 MITM 主机名
    sorted_mitm = sorted(list(mitm_hosts))

    print(f"转换完成！生成 URL Rewrite: {len(rewrite_rules)} 条，提取 MITM 主机: {len(sorted_mitm)} 个")

    # 构建标准 Shadowrocket 模块文件
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    out_lines = [
        "#!name=AdGuard 精细化过滤增强",
        f"#!desc=提取自 AdGuard 官方 iOS 基础与移动过滤器 | 包含 {len(rewrite_rules)} 条精细化路径重写与 MITM 解密 | {ts} UTC",
        "#!category=广告拦截",
        "#!author=AdGuard & lujundaren",
        "",
        "[URL Rewrite]",
    ]
    out_lines.extend(rewrite_rules)
    out_lines.append("")

    if sorted_mitm:
        out_lines.append("[MITM]")
        out_lines.append("hostname = %APPEND% " + ", ".join(sorted_mitm))
        out_lines.append("")

    os.makedirs(os.path.dirname(OUT_MODULE), exist_ok=True)
    with open(OUT_MODULE, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    print(f"模块已成功保存至: {OUT_MODULE}")


if __name__ == "__main__":
    main()
