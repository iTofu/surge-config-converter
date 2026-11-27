"""Tests for Surge v5+ → v4 configuration converter."""

import re
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

import converter
from converter import (
    ConversionStats,
    _split_top_level_commas,
    comment_line,
    compute_sections,
    convert_content,
    convert_file,
    extract_proxy_type,
    extract_rule_policy,
    format_proxy_group_line,
    has_effective_members,
    make_v4_filename,
    parse_proxy_group_line,
    ProxyGroupLine,
    remove_proxy_params,
    unquote,
    V5PLUS_ONLY_PROXY_PARAMS,
)


# --- Helpers ---

@pytest.fixture(autouse=True)
def _isolated_config_home(tmp_path_factory, monkeypatch):
    """Keep main() away from the real default snell legacy override file."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("xdg")))


def convert(text, base_dir="/tmp", stats=None, processed_files=None, filename=""):
    """Shorthand for convert_content with defaults."""
    if stats is None:
        stats = ConversionStats()
    if processed_files is None:
        processed_files = {}
    return convert_content(textwrap.dedent(text).strip(), base_dir, stats, processed_files, filename=filename)


# --- T1: Proxy protocol commenting ---

class TestProxyProtocolCommenting:
    def test_hysteria2_commented(self):
        result = convert("""
            [Proxy]
            US-HY2 = hysteria2, 1.2.3.4, 443, password=pwd, download-bandwidth=100
        """)
        assert "# [V5+] US-HY2 = hysteria2" in result

    def test_hy2_shorthand_commented(self):
        result = convert("""
            [Proxy]
            US-HY2 = hy2, 1.2.3.4, 443, password=pwd
        """)
        assert "# [V5+] US-HY2 = hy2" in result

    def test_anytls_commented(self):
        result = convert("""
            [Proxy]
            JP-ANYTLS = anytls, 5.6.7.8, 443, password=pwd
        """)
        assert "# [V5+] JP-ANYTLS = anytls" in result

    def test_tuic_commented(self):
        result = convert("""
            [Proxy]
            SG-TUIC = tuic, 9.10.11.12, 443, token=pwd, alpn=h3
        """)
        assert "# [V5+] SG-TUIC = tuic" in result

    def test_trust_tunnel_commented(self):
        result = convert("""
            [Proxy]
            US-TT = trust-tunnel, 1.2.3.4, 443, password=pwd
        """)
        assert "# [V5+] US-TT = trust-tunnel" in result

    def test_supported_protocols_unchanged(self):
        input_text = textwrap.dedent("""
            [Proxy]
            US-SNELL = snell, 1.2.3.4, 8000, psk=password, version=4
            HK-TROJAN = trojan, 1.2.3.4, 443, password=pwd
            JP-SS = ss, 1.2.3.4, 8000, encrypt-method=chacha20-ietf-poly1305, password=pwd
            US-VMESS = vmess, 1.2.3.4, 8000, username=uuid-here
        """).strip()
        result = convert(input_text)
        # None should be commented
        for line in result.splitlines():
            if line.startswith("["):
                continue
            assert not line.startswith("# [V5+]"), f"Should not be commented: {line}"

    def test_mixed_protocols(self):
        result = convert("""
            [Proxy]
            US-HY2 = hysteria2, 1.2.3.4, 443, password=pwd, download-bandwidth=100
            US-SNELL = snell, 1.2.3.4, 8000, psk=password, version=4
            JP-ANYTLS = anytls, 5.6.7.8, 443, password=pwd
            SG-TUIC = tuic, 9.10.11.12, 443, token=pwd, alpn=h3
            HK-TROJAN = trojan, 1.2.3.4, 443, password=pwd
        """)
        lines = result.splitlines()
        assert lines[1].startswith("# [V5+]")  # hysteria2
        assert not lines[2].startswith("# [V5+]")  # snell
        assert lines[3].startswith("# [V5+]")  # anytls
        assert lines[4].startswith("# [V5+]")  # tuic
        assert not lines[5].startswith("# [V5+]")  # trojan


# --- T2: Snell version=5 → version=4 ---

class TestSnellVersion:
    def test_version5_to_4(self):
        result = convert("""
            [Proxy]
            US-SNELL = snell, x.com, 27443, psk=xxx, version=5, tfo=true
        """)
        assert "version=4" in result
        assert "version=5" not in result

    def test_version4_unchanged(self):
        result = convert("""
            [Proxy]
            US-SNELL = snell, x.com, 27443, psk=xxx, version=4, tfo=true
        """)
        assert "version=4" in result

    def test_stats_counted(self):
        stats = ConversionStats()
        convert("""
            [Proxy]
            S1 = snell, x.com, 1, psk=a, version=5
            S2 = snell, y.com, 2, psk=b, version=5
        """, stats=stats)
        assert stats.params_modified == 2


# --- T3: shadow-tls-version=3 → 2 ---

class TestShadowTls:
    def test_version3_to_2(self):
        result = convert("""
            [Proxy]
            US-SS = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password=pwd, shadow-tls-version=3, shadow-tls-password=stpwd
        """)
        assert "shadow-tls-version=2" in result
        assert "shadow-tls-version=3" not in result
        assert "shadow-tls-password=stpwd" in result


# --- T4: Remove port-hopping / ecn parameters ---

class TestRemoveV5Params:
    def test_port_hopping_removed_on_supported_proxy(self):
        """For a v4-supported proxy type, v5+ only params should be stripped."""
        stats = ConversionStats()
        result = convert("""
            [Proxy]
            SS1 = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password=pwd, port-hopping="5000-6000", port-hopping-interval=30
        """, stats=stats)
        assert "port-hopping" not in result
        assert "SS1 = ss" in result

    def test_ecn_removed_on_supported_proxy(self):
        stats = ConversionStats()
        result = convert("""
            [Proxy]
            SNELL1 = snell, 1.2.3.4, 8000, psk=pwd, version=4, ecn=true
        """, stats=stats)
        assert "ecn=" not in result
        assert "SNELL1 = snell" in result

    def test_v5plus_proxy_with_v5plus_params_just_commented(self):
        """v5+ only proxy types are fully commented, params don't matter."""
        result = convert("""
            [Proxy]
            HY2 = hysteria2, 1.2.3.4, 443, password=pwd, port-hopping="5000-6000", ecn=true
        """)
        assert result.splitlines()[1].startswith("# [V5+]")


# --- T5: smart → url-test ---

class TestSmartToUrlTest:
    def test_smart_replaced(self):
        result = convert("""
            [Proxy Group]
            Auto = smart, policy-path=proxies.conf, interval=300
        """)
        assert "= url-test," in result
        assert "smart" not in result

    def test_select_unchanged(self):
        result = convert("""
            [Proxy Group]
            Manual = select, DIRECT, Proxy
        """)
        assert "= select," in result

    def test_multiple_smart_groups(self):
        result = convert("""
            [Proxy Group]
            Auto = smart, include-all-proxies=1, interval=300
            Region-HK = smart, include-all-proxies=1, policy-regex-filter=(HK|Hong Kong), hidden=true
        """)
        assert result.count("url-test") == 2
        assert "smart" not in result


# --- T6: v5+ only rule types ---

class TestV5OnlyRules:
    def test_hostname_type_commented(self):
        result = convert("""
            [Rule]
            HOSTNAME-TYPE,IPv4,Proxy
        """)
        assert "# [V5+] HOSTNAME-TYPE" in result

    def test_domain_wildcard_commented(self):
        result = convert("""
            [Rule]
            DOMAIN-WILDCARD,*.test?.com,Proxy
        """)
        assert "# [V5+] DOMAIN-WILDCARD" in result

    def test_supported_rules_unchanged(self):
        result = convert("""
            [Rule]
            DOMAIN-SUFFIX,example.com,DIRECT
            GEOIP,CN,DIRECT
            FINAL,Proxy,dns-failed
        """)
        for line in result.splitlines():
            if line.startswith("["):
                continue
            assert not line.startswith("# [V5+]")

    def test_mixed_rules(self):
        result = convert("""
            [Rule]
            DOMAIN-SUFFIX,example.com,DIRECT
            HOSTNAME-TYPE,IPv4,Proxy
            DOMAIN-WILDCARD,*.test?.com,Proxy
            GEOIP,CN,DIRECT
        """)
        lines = result.splitlines()
        assert not lines[1].startswith("# [V5+]")  # DOMAIN-SUFFIX
        assert lines[2].startswith("# [V5+]")  # HOSTNAME-TYPE
        assert lines[3].startswith("# [V5+]")  # DOMAIN-WILDCARD
        assert not lines[4].startswith("# [V5+]")  # GEOIP


# --- T7: [General] v5+ only parameters ---

class TestGeneralParams:
    def test_udp_priority_commented(self):
        result = convert("""
            [General]
            loglevel = notify
            udp-priority = true
            dns-server = 119.29.29.29
        """)
        assert "# [V5+] udp-priority = true" in result
        assert "loglevel = notify" in result
        assert "dns-server = 119.29.29.29" in result

    def test_block_quic_commented(self):
        result = convert("""
            [General]
            block-quic = all-proxy
        """)
        assert "# [V5+] block-quic = all-proxy" in result

    def test_supported_params_unchanged(self):
        result = convert("""
            [General]
            loglevel = notify
            dns-server = 119.29.29.29
            skip-proxy = localhost
        """)
        for line in result.splitlines():
            if line.startswith("[") or not line.strip():
                continue
            assert not line.startswith("# [V5+]")


# --- T8: [Port Forwarding] / [Body Rewrite] full section commenting ---

class TestV5OnlySections:
    def test_port_forwarding_commented(self):
        result = convert("""
            [Rule]
            FINAL,Proxy

            [Port Forwarding]
            0.0.0.0:6841 localhost:3306 policy=SQL-Proxy
            0.0.0.0:8080 localhost:80

            [MITM]
            hostname = *.example.com
        """)
        lines = result.splitlines()
        # Find Port Forwarding section
        pf_idx = next(i for i, l in enumerate(lines) if "Port Forwarding" in l)
        assert lines[pf_idx] == "# [V5+] [Port Forwarding]"
        assert lines[pf_idx + 1].startswith("# [V5+]")
        assert lines[pf_idx + 2].startswith("# [V5+]")
        # MITM section should not be commented
        mitm_idx = next(i for i, l in enumerate(lines) if "MITM" in l)
        assert lines[mitm_idx] == "[MITM]"
        assert "hostname = *.example.com" in result

    def test_body_rewrite_commented(self):
        result = convert("""
            [Body Rewrite]
            http-response ^https://api.example.com jq '.data'
        """)
        assert "# [V5+] [Body Rewrite]" in result
        assert "# [V5+] http-response" in result

    def test_empty_lines_in_v5plus_section_preserved(self):
        result = convert("""
            [Port Forwarding]
            line1

            line2
        """)
        lines = result.splitlines()
        assert lines[0] == "# [V5+] [Port Forwarding]"
        assert lines[1] == "# [V5+] line1"
        assert lines[2] == ""  # empty line not commented
        assert lines[3] == "# [V5+] line2"


# --- T9: #!include path update + recursive conversion ---

class TestIncludeDirective:
    def test_include_paths_updated(self, tmp_path):
        # Create referenced files
        proxies = tmp_path / "proxies.conf"
        proxies.write_text(
            "HY2-US = hysteria2, 1.2.3.4, 443, password=pwd\n"
            "SNELL-JP = snell, 5.6.7.8, 8000, psk=xxx, version=5\n"
            "TROJAN-HK = trojan, 9.10.11.12, 443, password=pwd\n"
        )
        extra = tmp_path / "extra.dconf"
        extra.write_text("SS1 = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password=pwd\n")

        # Create main file
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include proxies.conf, extra.dconf\n")

        stats = ConversionStats()
        processed = {str(main): None}
        output = convert_file(str(main), stats, processed)

        # Check main output
        main_v4 = tmp_path / "v4" / "main-v4.conf"
        assert main_v4.exists()
        content = main_v4.read_text()
        # extra.dconf needs no conversion but is still copied: v4/ is self-contained
        assert "#!include proxies-v4.conf, extra-v4.dconf" in content
        assert (tmp_path / "v4" / "extra-v4.dconf").exists()

        # Check proxies-v4.conf (has v5+ content)
        proxies_v4 = tmp_path / "v4" / "proxies-v4.conf"
        assert proxies_v4.exists()
        p_content = proxies_v4.read_text()
        assert "# [V5+] HY2-US = hysteria2" in p_content
        assert "version=4" in p_content
        assert "version=5" not in p_content
        assert "TROJAN-HK = trojan" in p_content

        # extra.dconf is pure v4: its copy is verbatim
        assert (tmp_path / "v4" / "extra-v4.dconf").read_text() == extra.read_text()

    def test_include_extra_spaces_no_false_positive(self, tmp_path):
        """#!include 行有多余空格时不应误判为内容变化"""
        sub = tmp_path / "sub.conf"
        sub.write_text("T1 = trojan, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include   sub.conf\n")  # 3个空格

        stats = ConversionStats()
        processed = {str(main): None}
        result = convert_file(str(main), stats, processed)

        assert result is None
        assert not (tmp_path / "v4" / "main-v4.conf").exists()

    def test_include_with_nonexistent_file(self, tmp_path):
        """References to nonexistent files keep original path."""
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include missing.conf\n")

        stats = ConversionStats()
        processed = {str(main): None}
        result = convert_file(str(main), stats, processed)

        # No changes needed (nonexistent file keeps original reference)
        assert result is None


# --- T10: policy-path local path update (skip HTTP URLs) ---

class TestPolicyPath:
    def test_local_path_updated_when_changed(self, tmp_path):
        local_proxies = tmp_path / "local-proxies.conf"
        local_proxies.write_text("HY2 = hysteria2, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Proxy = select, policy-path=local-proxies.conf\n"
        )

        stats = ConversionStats()
        processed = {str(main): None}
        convert_file(str(main), stats, processed)

        content = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "policy-path=local-proxies-v4.conf" in content
        assert (tmp_path / "v4" / "local-proxies-v4.conf").exists()

    def test_local_path_unchanged_when_no_changes(self, tmp_path):
        local_proxies = tmp_path / "local-proxies.conf"
        local_proxies.write_text("T1 = trojan, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Proxy = select, policy-path=local-proxies.conf\n"
        )

        stats = ConversionStats()
        processed = {str(main): None}
        result = convert_file(str(main), stats, processed)

        # No changes needed anywhere
        assert result is None
        assert not (tmp_path / "v4" / "local-proxies-v4.conf").exists()

    def test_http_url_unchanged(self):
        result = convert("""
            [Proxy Group]
            Auto = smart, policy-path=https://sub.example.com/surge.conf, interval=300
        """)
        assert "policy-path=https://sub.example.com/surge.conf" in result
        assert "url-test" in result  # smart should still be converted

    def test_mixed_local_and_http(self, tmp_path):
        local = tmp_path / "profile.dconf"
        local.write_text("S1 = snell, 1.2.3.4, 8000, psk=x, version=4\n")

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Proxy = select, policy-path=profile.dconf\n"
            "Auto = smart, policy-path=https://sub.example.com/surge.conf, interval=300\n"
        )

        stats = ConversionStats()
        processed = {str(main): None}
        convert_file(str(main), stats, processed)

        content = (tmp_path / "v4" / "main-v4.conf").read_text()
        # profile.dconf is pure v4 but still copied: v4/ is self-contained
        assert "policy-path=profile-v4.dconf" in content
        assert (tmp_path / "v4" / "profile-v4.dconf").exists()
        assert "policy-path=https://sub.example.com/surge.conf" in content

    def test_multiple_policy_path_refs_to_same_file_all_rewritten(self, tmp_path):
        """Regression: the same sub-file referenced by BOTH an #!include and
        multiple policy-path options must have ALL references rewritten to -v4,
        not just the first encounter."""
        sub = tmp_path / "work.dconf"
        sub.write_text(
            "[Proxy]\nSNELL = snell, 1.2.3.4, 8000, psk=pwd, version=5\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include work.dconf\n"
            "\n"
            "[Proxy Group]\n"
            "G1 = select, policy-path=work.dconf\n"
            "G2 = select, policy-path=work.dconf\n"
            "G3 = select, policy-path=work.dconf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include work-v4.dconf" in out
        # All three references must be rewritten, not just the first
        assert out.count("policy-path=work-v4.dconf") == 3
        assert "policy-path=work.dconf" not in out


# --- T11: Output file conflict backup ---

class TestBackup:
    def test_existing_output_backed_up(self, tmp_path):
        main = tmp_path / "output.conf"
        main.write_text("[General]\nudp-priority = true\n")

        # Create existing output in v4/ subdirectory
        (tmp_path / "v4").mkdir()
        existing = tmp_path / "v4" / "output-v4.conf"
        existing.write_text("old content")

        stats = ConversionStats()
        processed = {str(main): None}
        convert_file(str(main), stats, processed)

        # New file should exist
        assert existing.exists()
        assert existing.read_text() != "old content"

        # Backup file should exist (in v4/ alongside the output)
        backup = tmp_path / "v4" / "output-v4-deprecated.conf"
        assert backup.exists()
        assert backup.read_text() == "old content"

    def test_deprecated_files_tracked_in_stats(self, tmp_path):
        """backup_if_exists 产生的文件应记录到 stats.deprecated_files"""
        main = tmp_path / "output.conf"
        main.write_text("[General]\nudp-priority = true\n")

        (tmp_path / "v4").mkdir()
        existing = tmp_path / "v4" / "output-v4.conf"
        existing.write_text("old content")

        stats = ConversionStats()
        processed = {str(main): None}
        convert_file(str(main), stats, processed)

        assert len(stats.deprecated_files) == 1
        assert str(tmp_path / "v4" / "output-v4-deprecated.conf") in stats.deprecated_files

    def test_no_backup_when_no_conflict(self, tmp_path):
        main = tmp_path / "output.conf"
        main.write_text("[General]\nudp-priority = true\n")

        stats = ConversionStats()
        processed = {str(main): None}
        convert_file(str(main), stats, processed)

        assert not (tmp_path / "v4" / "output-v4-deprecated.conf").exists()

    def test_second_run_skips_when_content_matches(self, tmp_path):
        main = tmp_path / "output.conf"
        main.write_text("[General]\nudp-priority = true\n")

        # First run: create output-v4.conf from stale content
        (tmp_path / "v4").mkdir()
        existing = tmp_path / "v4" / "output-v4.conf"
        existing.write_text("first content")
        convert_file(str(main), ConversionStats(), {str(main): None})

        # First run backed up "first content" to deprecated
        backup = tmp_path / "v4" / "output-v4-deprecated.conf"
        assert backup.exists()
        assert backup.read_text() == "first content"

        # Second run: -v4 content matches, should skip entirely
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert len(stats.files_processed) == 0
        assert len(stats.deprecated_files) == 0


# --- T11b: Skip unchanged sub-files ---

class TestSkipUnchangedSubfile:
    def test_pure_v4_subfile_skipped(self, tmp_path):
        """Sub-file with no v5+ content → no -v4 copy, no output at all."""
        proxies = tmp_path / "proxies.conf"
        proxies.write_text("T1 = trojan, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include proxies.conf\n")

        stats = ConversionStats()
        processed = {str(main): None}
        result = convert_file(str(main), stats, processed)

        # Nothing needs conversion anywhere
        assert result is None
        assert not (tmp_path / "v4" / "proxies-v4.conf").exists()
        assert not (tmp_path / "v4" / "main-v4.conf").exists()

    def test_mixed_subfiles(self, tmp_path):
        """Once anything emits, every reachable sub-file gets a -v4 copy —
        v4/ must be self-contained, a bare `pure.conf` would dangle there."""
        pure_v4 = tmp_path / "pure.conf"
        pure_v4.write_text("T1 = trojan, 1.2.3.4, 443, password=pwd\n")

        needs_conv = tmp_path / "needs-conv.conf"
        needs_conv.write_text("HY2 = hysteria2, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include pure.conf, needs-conv.conf\n")

        stats = ConversionStats()
        processed = {str(main): None}
        convert_file(str(main), stats, processed)

        assert (tmp_path / "v4" / "needs-conv-v4.conf").exists()
        assert (tmp_path / "v4" / "pure-v4.conf").read_text() == pure_v4.read_text()
        content = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include pure-v4.conf, needs-conv-v4.conf" in content

    def test_clean_policy_path_subfile_copied_when_tree_emits(self, tmp_path):
        """policy-path to a v4-clean file from a converted root → copied and
        the reference rewritten, never left pointing at a missing v4/ file."""
        res = tmp_path / "res.dconf"
        res.write_text("[Proxy]\nR1 = http, 1.2.3.4, 18080, username=u, password=p\n")

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Auto = smart, R1\n"
            "Res = select, policy-path=res.dconf\n"
        )

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})

        assert (tmp_path / "v4" / "res-v4.dconf").read_text() == res.read_text()
        content = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "policy-path=res-v4.dconf" in content
        assert "policy-path=res.dconf" not in content

    def test_every_local_reference_resolves_inside_v4(self, tmp_path):
        """Invariant: each local include / policy-path in any emitted file
        names a file that exists in v4/."""
        (tmp_path / "a.dconf").write_text("[Proxy]\nA = trojan, 1.1.1.1, 443, password=x\n")
        (tmp_path / "b.dconf").write_text("[Proxy]\nB = hysteria2, 2.2.2.2, 443, password=x\n")
        (tmp_path / "c.conf").write_text("[Proxy]\n#!include a.dconf\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n#!include c.conf, b.dconf\n"
            "[Proxy Group]\nG = select, policy-path=a.dconf\n"
        )

        convert_file(str(main), ConversionStats(), {str(main): None})

        v4 = tmp_path / "v4"
        for out in v4.iterdir():
            for line in out.read_text().splitlines():
                refs = []
                if line.startswith("#!include"):
                    refs = [e.strip() for e in line[len("#!include"):].split(",")]
                refs += re.findall(r"policy-path=([^,\s]+)", line)
                for ref in refs:
                    assert (v4 / ref).exists(), f"{out.name}: {ref} missing in v4/"

    def test_clean_managed_subfile_abandoned_not_dangling(self, tmp_path):
        """A managed sub-file must not be copied (Surge's refresh would
        overwrite the copy), so when the tree emits it is abandoned and its
        reference stripped instead of left dangling."""
        (tmp_path / "sub.conf").write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=43200\n"
            "[Proxy]\nHK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        (tmp_path / "own.conf").write_text("OWN = hysteria2, 1.2.3.4, 443, password=pwd\n")
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include sub.conf, own.conf\n")

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})

        assert str(tmp_path / "sub.conf") in stats.abandoned_files
        assert not (tmp_path / "v4" / "sub-v4.conf").exists()
        content = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include own-v4.conf" in content
        assert "sub.conf" not in content

    def test_policy_path_subfile_skipped(self, tmp_path):
        """policy-path sub-file with no changes → keep original reference."""
        local = tmp_path / "profile.dconf"
        local.write_text("S1 = snell, 1.2.3.4, 8000, psk=x, version=4\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy Group]\nProxy = select, policy-path=profile.dconf\n")

        stats = ConversionStats()
        processed = {str(main): None}
        result = convert_file(str(main), stats, processed)

        assert result is None
        assert not (tmp_path / "v4" / "profile-v4.dconf").exists()

    def test_main_file_pure_v4_returns_none(self, tmp_path):
        """Entry file with no v5+ content → no output file, returns None."""
        main = tmp_path / "main.conf"
        main.write_text("[General]\nloglevel = notify\n")

        stats = ConversionStats()
        processed = {str(main): None}
        result = convert_file(str(main), stats, processed)

        assert result is None
        assert not (tmp_path / "v4" / "main-v4.conf").exists()


# --- T12: Already-commented lines not double-processed ---

class TestAlreadyCommented:
    def test_commented_line_unchanged(self):
        result = convert("""
            [Proxy]
            # HY2-OLD = hysteria2, 1.2.3.4, 443, password=pwd
            SNELL-US = snell, 1.2.3.4, 8000, psk=xxx, version=4
        """)
        lines = result.splitlines()
        assert lines[1] == "# HY2-OLD = hysteria2, 1.2.3.4, 443, password=pwd"
        assert not lines[1].startswith("# [V5+]")

    def test_commented_rule_unchanged(self):
        result = convert("""
            [Rule]
            # HOSTNAME-TYPE,IPv4,Proxy
            DOMAIN-SUFFIX,example.com,DIRECT
        """)
        assert "# HOSTNAME-TYPE" in result
        assert "# [V5+]" not in result


# --- T13: No-op for pure v4 config ---

class TestNoOp:
    def test_pure_v4_config_unchanged(self):
        input_text = textwrap.dedent("""
            [General]
            loglevel = notify
            dns-server = 119.29.29.29

            [Proxy]
            HK-TROJAN = trojan, 1.2.3.4, 443, password=pwd
            US-SS = ss, 5.6.7.8, 8000, encrypt-method=chacha20-ietf-poly1305, password=pwd

            [Proxy Group]
            Proxy = select, HK-TROJAN, US-SS
            Auto = url-test, HK-TROJAN, US-SS, interval=300

            [Rule]
            DOMAIN-SUFFIX,example.com,DIRECT
            GEOIP,CN,DIRECT
            FINAL,Proxy
        """).strip()
        stats = ConversionStats()
        result = convert(input_text, stats=stats)
        assert result == input_text
        assert stats.lines_commented == 0
        assert stats.params_modified == 0


# --- T14: Conversion summary ---

class TestConversionSummary:
    def test_stats_tracking(self):
        stats = ConversionStats()
        convert("""
            [General]
            udp-priority = true
            block-quic = all

            [Proxy]
            HY2 = hysteria2, 1.2.3.4, 443, password=pwd
            SNELL = snell, 1.2.3.4, 8000, psk=pwd, version=5
            ANYTLS = anytls, 5.6.7.8, 443, password=pwd

            [Proxy Group]
            Auto = smart, interval=300

            [Rule]
            HOSTNAME-TYPE,IPv4,Proxy
            DOMAIN-WILDCARD,*.test.com,DIRECT
        """, stats=stats)
        # Commented: udp-priority, block-quic, HY2, ANYTLS, HOSTNAME-TYPE, DOMAIN-WILDCARD = 6
        assert stats.lines_commented == 6
        # Modified: version=5→4, smart→url-test = 2
        assert stats.params_modified == 2


# --- Utility function tests ---

class TestMakeV4Filename:
    def test_conf(self):
        assert make_v4_filename("/path/to/profile.conf") == "/path/to/v4/profile-v4.conf"

    def test_dconf(self):
        assert make_v4_filename("/path/to/own-vps.dconf") == "/path/to/v4/own-vps-v4.dconf"

    def test_relative(self):
        assert make_v4_filename("proxies.conf") == "v4/proxies-v4.conf"


class TestMakeV4Relname:
    def test_bare_filename(self):
        from converter import make_v4_relname
        assert make_v4_relname("work-vps.dconf") == "work-vps-v4.dconf"

    def test_strips_directory(self):
        from converter import make_v4_relname
        assert make_v4_relname("subdir/file.conf") == "file-v4.conf"

    def test_absolute_path(self):
        from converter import make_v4_relname
        assert make_v4_relname("/abs/path/profile.conf") == "profile-v4.conf"


class TestExtractProxyType:
    def test_standard(self):
        assert extract_proxy_type("US-HY2 = hysteria2, 1.2.3.4, 443") == "hysteria2"

    def test_with_emoji(self):
        assert extract_proxy_type("🇺🇸 US = snell, x.com, 443, psk=x, version=4") == "snell"

    def test_commented(self):
        # Commented lines should not match
        assert extract_proxy_type("# US = hysteria2, 1.2.3.4, 443") is None

    def test_no_equals(self):
        assert extract_proxy_type("some random line") is None


class TestCommentLine:
    def test_basic(self):
        assert comment_line("some line") == "# [V5+] some line"


class TestRemoveProxyParams:
    def test_remove_single(self):
        line = "X = ss, 1.2.3.4, 8000, password=pwd, ecn=true"
        result, removed = remove_proxy_params(line, {"ecn"})
        assert "ecn" not in result
        assert removed == ["ecn"]

    def test_remove_multiple(self):
        line = 'X = tuic, 1.2.3.4, 443, token=pwd, port-hopping="5000-6000", port-hopping-interval=30, ecn=true'
        result, removed = remove_proxy_params(line, {"port-hopping", "port-hopping-interval", "ecn"})
        assert "port-hopping" not in result
        assert "ecn" not in result
        assert len(removed) == 3

    def test_no_match(self):
        line = "X = ss, 1.2.3.4, 8000, password=pwd"
        result, removed = remove_proxy_params(line, {"ecn"})
        assert result == line
        assert removed == []


# --- T15: Change output ---

class TestChangeOutput:
    def test_changes_recorded(self):
        stats = ConversionStats()
        convert("""
            [General]
            udp-priority = true

            [Proxy]
            HY2 = hysteria2, 1.2.3.4, 443, password=pwd
            SNELL = snell, 1.2.3.4, 8000, psk=pwd, version=5

            [Proxy Group]
            Auto = smart, interval=300
        """, stats=stats, filename="test.conf")
        assert len(stats.changes) == 4
        fn, ln, sec, act, det = stats.changes[0]
        assert fn == "test.conf" and ln == 2 and "udp-priority" in det
        assert stats.changes[1][4] == "HY2 (hysteria2)"
        assert stats.changes[2][3] == "version=5 → version=4"
        assert stats.changes[3][3] == "smart → url-test"

    def test_v5plus_section_recorded(self):
        stats = ConversionStats()
        convert("""
            [Port Forwarding]
            0.0.0.0:6841 localhost:3306
        """, stats=stats, filename="test.conf")
        assert len(stats.changes) == 1
        fn, ln, sec, act, det = stats.changes[0]
        assert fn == "test.conf" and act == "注释段" and "[Port Forwarding]" in det

    def test_rule_comment_recorded(self):
        stats = ConversionStats()
        convert("""
            [Rule]
            HOSTNAME-TYPE,IPv4,Proxy
        """, stats=stats, filename="test.conf")
        assert len(stats.changes) == 1
        fn, ln, sec, act, det = stats.changes[0]
        assert act == "注释" and "HOSTNAME-TYPE,IPv4,Proxy" in det

    def test_remove_param_recorded(self):
        stats = ConversionStats()
        convert("""
            [Proxy]
            SNELL1 = snell, 1.2.3.4, 8000, psk=pwd, version=4, ecn=true
        """, stats=stats, filename="test.conf")
        assert len(stats.changes) == 1
        fn, ln, sec, act, det = stats.changes[0]
        assert act == "移除参数" and "ecn" in det and "SNELL1" in det


# --- T16: Skip unchanged -v4 files ---

class TestSkipUnchangedV4:
    def test_skip_when_v4_content_matches(self, tmp_path):
        """Second run should skip when -v4 already has correct content."""
        main = tmp_path / "output.conf"
        main.write_text("[General]\nudp-priority = true\n")

        # First run: creates output-v4.conf
        stats1 = ConversionStats()
        convert_file(str(main), stats1, {str(main): None})
        v4 = tmp_path / "v4" / "output-v4.conf"
        assert v4.exists()
        first_content = v4.read_text()

        # Second run: should skip, no deprecated file
        stats2 = ConversionStats()
        result = convert_file(str(main), stats2, {str(main): None})
        assert result == str(v4)
        assert v4.read_text() == first_content
        assert not (tmp_path / "v4" / "output-v4-deprecated.conf").exists()
        assert len(stats2.files_processed) == 0
        assert len(stats2.deprecated_files) == 0

    def test_overwrite_when_v4_content_differs(self, tmp_path):
        """Should overwrite when existing -v4 has different content."""
        main = tmp_path / "output.conf"
        main.write_text("[General]\nudp-priority = true\n")

        (tmp_path / "v4").mkdir()
        v4 = tmp_path / "v4" / "output-v4.conf"
        v4.write_text("stale content")

        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})
        assert result == str(v4)
        assert v4.read_text() != "stale content"
        assert (tmp_path / "v4" / "output-v4-deprecated.conf").exists()

    def test_subfile_skip_preserves_v4_reference(self, tmp_path):
        """When sub-file -v4 is skipped, parent still references -v4 path."""
        proxies = tmp_path / "proxies.conf"
        proxies.write_text("HY2 = hysteria2, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include proxies.conf\n")

        # First run
        convert_file(str(main), ConversionStats(), {str(main): None})

        # Second run
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})
        assert result is not None
        content = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "proxies-v4.conf" in content


# --- T17: Deprecated files sent to trash ---

class TestDeprecatedSendToTrash:
    def test_deprecated_files_sent_to_trash(self, tmp_path, monkeypatch):
        """main() should call send2trash instead of os.remove for deprecated files."""
        main_conf = tmp_path / "output.conf"
        main_conf.write_text("[General]\nudp-priority = true\n")

        # Create stale -v4 so a deprecated backup is generated
        (tmp_path / "v4").mkdir()
        existing = tmp_path / "v4" / "output-v4.conf"
        existing.write_text("old content")

        # Run convert_file to produce deprecated file
        import types
        from converter import main as converter_main

        monkeypatch.setattr("sys.argv", ["converter.py", str(main_conf)])
        monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
        monkeypatch.setattr("builtins.input", lambda _: "y")

        with patch("converter.send2trash") as mock_trash:
            converter_main()
            assert mock_trash.call_count == 1
            trashed = mock_trash.call_args[0][0]
            assert "deprecated" in trashed


# --- T18: Managed config detection ---

class TestIsManagedConfig:
    def test_managed_on_first_line(self):
        from converter import is_managed_config
        assert is_managed_config("#!MANAGED-CONFIG https://x.com/a.conf interval=3600\n[General]\n")

    def test_managed_with_strict(self):
        from converter import is_managed_config
        assert is_managed_config("#!MANAGED-CONFIG https://x.com/a.conf interval=3600 strict=true\n")

    def test_not_managed_plain(self):
        from converter import is_managed_config
        assert not is_managed_config("[General]\nloglevel = notify\n")

    def test_not_managed_if_after_header(self):
        """Must be on the very first non-blank line. Anything non-blank before it disqualifies."""
        from converter import is_managed_config
        assert not is_managed_config("[General]\n#!MANAGED-CONFIG https://x.com/a.conf\n")

    def test_not_managed_if_commented(self):
        from converter import is_managed_config
        assert not is_managed_config("# #!MANAGED-CONFIG https://x.com/a.conf\n[General]\n")

    def test_leading_blank_lines_allowed(self):
        """Tolerate leading blank lines before the directive."""
        from converter import is_managed_config
        assert is_managed_config("\n\n#!MANAGED-CONFIG https://x.com/a.conf\n[General]\n")

    def test_empty_string(self):
        from converter import is_managed_config
        assert not is_managed_config("")


# --- T19: Managed config abandonment ---

class TestManagedAbandon:
    def test_managed_with_v5plus_is_abandoned(self, tmp_path):
        main = tmp_path / "sub.conf"
        main.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=43200 strict=true\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})

        assert result is None
        assert not (tmp_path / "v4" / "sub-v4.conf").exists()
        assert str(main) in stats.abandoned_files

    def test_managed_without_v5plus_passes_through(self, tmp_path):
        """Managed profile with no v5+ content → no change needed, no abandon."""
        main = tmp_path / "sub.conf"
        main.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=43200\n"
            "[Proxy]\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})

        assert result is None
        assert not (tmp_path / "v4" / "sub-v4.conf").exists()
        assert str(main) not in stats.abandoned_files

    def test_non_managed_with_v5plus_still_converts(self, tmp_path):
        """Non-managed file: abandon rule does not apply."""
        main = tmp_path / "sub.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})

        assert result == str(tmp_path / "v4" / "sub-v4.conf")
        assert (tmp_path / "v4" / "sub-v4.conf").exists()
        assert stats.abandoned_files == []

    def test_stale_v4_detected_but_not_deleted_on_abandon(self, tmp_path):
        """If a -v4 file exists from a previous run, abandoning records it in
        stats.stale_v4_files WITHOUT deleting it."""
        main = tmp_path / "sub.conf"
        main.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=43200\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        (tmp_path / "v4").mkdir()
        stale = tmp_path / "v4" / "sub-v4.conf"
        stale.write_text("stale content from earlier converter run")

        stats = ConversionStats()
        with patch("converter.send2trash") as mock_trash:
            convert_file(str(main), stats, {str(main): None})
            assert mock_trash.call_count == 0

        assert stale.exists()
        assert stale.read_text() == "stale content from earlier converter run"
        assert str(main) in stats.abandoned_files
        assert str(stale) in stats.stale_v4_files


# --- T20: Proxy Group line parsing ---

class TestParseProxyGroupLine:
    def test_select_with_members_only(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line("Proxy = select, DIRECT, HK, JP")
        assert pgl.name == "Proxy"
        assert pgl.group_type == "select"
        assert pgl.members == ["DIRECT", "HK", "JP"]
        assert pgl.options == []

    def test_select_with_quoted_members(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line('✈️ Proxy = select, "💼 Work", "♻️ Auto", DIRECT')
        assert pgl.name == "✈️ Proxy"
        assert pgl.members == ['"💼 Work"', '"♻️ Auto"', "DIRECT"]

    def test_url_test_with_options(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line("Auto = url-test, HK, JP, url=http://x.com/204, interval=300")
        assert pgl.group_type == "url-test"
        assert pgl.members == ["HK", "JP"]
        assert pgl.options == [("url", "http://x.com/204"), ("interval", "300")]

    def test_policy_path_is_an_option_not_a_member(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line("Auto = smart, policy-path=proxies.conf, interval=300")
        assert pgl.members == []
        assert pgl.options == [("policy-path", "proxies.conf"), ("interval", "300")]

    def test_mixed_members_and_policy_path(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line(
            'Proxy = select, "💼 Work", "♻️ Auto", policy-path=provider.conf'
        )
        assert pgl.members == ['"💼 Work"', '"♻️ Auto"']
        assert pgl.options == [("policy-path", "provider.conf")]

    def test_include_all_proxies_is_an_option(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line(
            "AI = select, REJECT, include-all-proxies=1, policy-regex-filter=(HK|JP)"
        )
        assert pgl.members == ["REJECT"]
        assert ("include-all-proxies", "1") in pgl.options

    def test_comment_line_returns_none(self):
        from converter import parse_proxy_group_line
        assert parse_proxy_group_line("# Proxy = select, HK") is None

    def test_section_header_returns_none(self):
        from converter import parse_proxy_group_line
        assert parse_proxy_group_line("[Proxy Group]") is None

    def test_extra_whitespace_tolerated(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line("  Proxy  =  select  ,  HK  ,  JP  ")
        assert pgl.name == "Proxy"
        assert pgl.group_type == "select"
        assert pgl.members == ["HK", "JP"]

    def test_duplicate_policy_path_preserved_as_list(self):
        """List-of-tuples for options preserves duplicate keys like two policy-paths."""
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line(
            "Mix = select, policy-path=https://x.com/a.conf, policy-path=sub.conf"
        )
        assert pgl.members == []
        assert pgl.options == [
            ("policy-path", "https://x.com/a.conf"),
            ("policy-path", "sub.conf"),
        ]


class TestFormatProxyGroupLine:
    def test_roundtrip_simple(self):
        from converter import parse_proxy_group_line, format_proxy_group_line
        line = "Proxy = select, DIRECT, HK, JP"
        assert format_proxy_group_line(parse_proxy_group_line(line)) == line

    def test_roundtrip_with_options(self):
        from converter import parse_proxy_group_line, format_proxy_group_line
        line = "Auto = url-test, HK, JP, url=http://x.com/204, interval=300"
        assert format_proxy_group_line(parse_proxy_group_line(line)) == line

    def test_roundtrip_quoted_members(self):
        from converter import parse_proxy_group_line, format_proxy_group_line
        line = '✈️ Proxy = select, "💼 Work", "♻️ Auto", DIRECT'
        assert format_proxy_group_line(parse_proxy_group_line(line)) == line

    def test_format_with_no_members(self):
        from converter import ProxyGroupLine, format_proxy_group_line
        pgl = ProxyGroupLine(
            name="Auto", group_type="url-test", members=[], options=[("interval", "300")]
        )
        assert format_proxy_group_line(pgl) == "Auto = url-test, interval=300"

    def test_format_with_empty_options(self):
        from converter import ProxyGroupLine, format_proxy_group_line
        pgl = ProxyGroupLine(
            name="Proxy", group_type="select", members=["HK", "JP"], options=[]
        )
        assert format_proxy_group_line(pgl) == "Proxy = select, HK, JP"


# --- T21: Rule policy extraction ---

class TestExtractRulePolicy:
    def test_domain_suffix(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("DOMAIN-SUFFIX,example.com,DIRECT") == "DIRECT"

    def test_quoted_policy(self):
        from converter import extract_rule_policy
        assert extract_rule_policy('DOMAIN,foo.com,"✈️ Proxy"') == '"✈️ Proxy"'

    def test_policy_with_emoji(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("DOMAIN,foo.com,♻️ Auto") == "♻️ Auto"

    def test_ip_cidr_with_no_resolve(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("IP-CIDR,1.2.3.4/32,DIRECT,no-resolve") == "DIRECT"

    def test_geoip_with_force_remote_dns(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("GEOIP,CN,DIRECT,force-remote-dns") == "DIRECT"

    def test_rule_set(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("RULE-SET,https://x.com/list.list,Proxy") == "Proxy"

    def test_and_rule(self):
        from converter import extract_rule_policy
        assert extract_rule_policy(
            "AND,((DOMAIN-SUFFIX,example.com),(DEST-PORT,443)),DIRECT"
        ) == "DIRECT"

    def test_or_rule_with_quoted_policy(self):
        from converter import extract_rule_policy
        assert extract_rule_policy(
            'OR,((DOMAIN,a.com),(DOMAIN,b.com)),"✈️ Proxy"'
        ) == '"✈️ Proxy"'

    def test_final_rule(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("FINAL,Proxy,dns-failed") == "Proxy"

    def test_comment_returns_none(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("# DOMAIN,foo.com,DIRECT") is None

    def test_section_header_returns_none(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("[Rule]") is None

    def test_empty_returns_none(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("") is None


# --- T22: Include list parsing ---

class TestParseIncludeList:
    def test_single_file(self):
        from converter import parse_include_list
        assert parse_include_list("#!include proxies.conf") == ["proxies.conf"]

    def test_multiple_files(self):
        from converter import parse_include_list
        assert parse_include_list("#!include a.conf, b.conf, c.dconf") == [
            "a.conf", "b.conf", "c.dconf",
        ]

    def test_extra_whitespace(self):
        from converter import parse_include_list
        assert parse_include_list("#!include   a.conf  ,  b.conf  ") == ["a.conf", "b.conf"]

    def test_url_and_local_mixed(self):
        from converter import parse_include_list
        assert parse_include_list(
            "#!include https://x.com/a.conf, local.conf"
        ) == ["https://x.com/a.conf", "local.conf"]

    def test_not_an_include(self):
        from converter import parse_include_list
        assert parse_include_list("[General]") is None
        assert parse_include_list("# comment") is None
        assert parse_include_list("") is None


class TestFormatIncludeList:
    def test_single(self):
        from converter import format_include_list
        assert format_include_list(["a.conf"]) == "#!include a.conf"

    def test_multiple(self):
        from converter import format_include_list
        assert format_include_list(["a.conf", "b.conf"]) == "#!include a.conf, b.conf"

    def test_empty_returns_none(self):
        """Empty list → None so caller knows to comment the whole line."""
        from converter import format_include_list
        assert format_include_list([]) is None


# --- T23: Pipeline skeleton regression ---

class TestPipelineSkeleton:
    def test_pipeline_runs_end_to_end(self, tmp_path):
        """Pipeline.run must produce the same output as the old convert_file."""
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\nHY = hysteria2, 1.2.3.4, 443, password=pwd\n")

        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})

        assert result == str(tmp_path / "v4" / "main-v4.conf")
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+]" in out

    def test_pipeline_skip_unchanged(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text("[General]\nloglevel = notify\n")

        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})
        assert result is None
        assert not (tmp_path / "v4" / "main-v4.conf").exists()

    def test_pipeline_include_recursion(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include sub.conf\n")

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})

        assert (tmp_path / "v4" / "sub-v4.conf").exists()
        assert (tmp_path / "v4" / "main-v4.conf").exists()
        main_out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include sub-v4.conf" in main_out


# --- T24: Single-file cascade (proxy → proxy group) ---

class TestSingleFileProxyCascade:
    def test_group_member_removed_when_proxy_deleted(self, tmp_path):
        """A v5+ proxy is commented; a group that listed it drops the reference."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Proxy = select, JP, HK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+] JP = anytls" in out
        assert "Proxy = select, HK" in out

    def test_group_becomes_empty_after_cascade(self, tmp_path):
        """A group with only v5+ members becomes empty → tag as cascade."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "US = hysteria2, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Fast = url-test, JP, US\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] Fast = url-test" in out

    def test_group_with_builtin_survives(self, tmp_path):
        """Group retaining a built-in policy is still valid."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Block = select, REJECT, JP, DIRECT\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "Block = select, REJECT, DIRECT" in out
        assert "# [V5+ cascade]" not in out

    def test_group_with_include_all_survives(self, tmp_path):
        """include-all-proxies=1 counts as implicit member supply."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Auto = url-test, JP, include-all-proxies=1, interval=300\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade]" not in out
        assert "Auto = url-test, include-all-proxies=1, interval=300" in out

    def test_cascade_propagates_to_referencing_group(self, tmp_path):
        """Group A loses all members → Group B that referenced A now has a dangling ref."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "Outer = select, OnlyV5, HK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] OnlyV5 = select" in out
        assert "Outer = select, HK" in out

    def test_pre_existing_empty_group_left_alone(self, tmp_path):
        """A group that was already empty before our cleanup must not be touched."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Auto = smart, interval=300\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        # smart → url-test still happens (direct hit)
        assert "Auto = url-test, interval=300" in out
        # but NO cascade tag, because we removed nothing from Auto
        assert "# [V5+ cascade]" not in out

    def test_quoted_member_cascade(self, tmp_path):
        """Quoted member names must also be recognized for deletion."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            '"🇯🇵 JP" = anytls, 1.2.3.4, 443, password=pwd\n'
            '"🇭🇰 HK" = trojan, 5.6.7.8, 443, password=pwd\n'
            "\n"
            "[Proxy Group]\n"
            'Proxy = select, "🇯🇵 JP", "🇭🇰 HK"\n'
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert 'Proxy = select, "🇭🇰 HK"' in out


# --- T25: Single-file cascade — rules ---

class TestSingleFileRuleCascade:
    def test_rule_commented_when_policy_deleted(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,foo.com,JP\n"
            "DOMAIN,bar.com,HK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] DOMAIN,foo.com,JP" in out
        assert "DOMAIN,bar.com,HK" in out  # unchanged

    def test_rule_with_cascade_deleted_group(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,foo.com,OnlyV5\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] OnlyV5 = select" in out
        assert "# [V5+ cascade] DOMAIN,foo.com,OnlyV5" in out

    def test_and_rule_cascade(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Rule]\n"
            "AND,((DOMAIN-SUFFIX,example.com),(DEST-PORT,443)),JP\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] AND,((DOMAIN-SUFFIX,example.com),(DEST-PORT,443)),JP" in out


# --- T26: Cross-file cascade — owned names propagate ---

class TestCrossFileOwnedNames:
    def test_abandoned_proxies_removed_from_parent_group(self, tmp_path):
        """When a sub-file is abandoned, proxy names defined inside it must
        propagate into the parent's deleted_names so the parent's Proxy Group
        members referencing those names (by name) get removed.

        (Include-line cleanup is Task 12 and tested separately.)"""
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "LOCAL = ss, 9.9.9.9, 443, encrypt-method=aes-256-gcm, password=pwd\n"
            "#!include sub.conf\n"
            "\n"
            "[Proxy Group]\n"
            "Proxy = select, LOCAL, JP, HK\n"
        )

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})

        assert not (tmp_path / "v4" / "sub-v4.conf").exists()
        assert str(sub) in stats.abandoned_files

        main_v4 = tmp_path / "v4" / "main-v4.conf"
        assert main_v4.exists()
        out = main_v4.read_text()

        # After cross-file propagation: JP and HK (defined in abandoned sub.conf)
        # must be removed from the Proxy group's member list. LOCAL stays.
        assert "Proxy = select, LOCAL" in out
        # Sanity: no stray JP/HK as members in the group line
        for out_line in out.splitlines():
            if out_line.startswith("Proxy = select"):
                # Members come after `select, ` until the first key=value
                members_part = out_line.split(" = select, ", 1)[1]
                members = [t.strip() for t in members_part.split(",") if "=" not in t]
                assert "JP" not in members
                assert "HK" not in members
                break
        else:
            assert False, "Proxy group line not found in output"


# --- T27: Cross-file cascade — policy-path → abandoned ---

class TestCrossFilePolicyPath:
    def test_policy_path_option_stripped(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "#!include sub.conf\n"
            "[Proxy Group]\n"
            'Proxy = select, "💼 Work", "🧑‍💻 VPS", policy-path=sub.conf\n'
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert 'Proxy = select, "💼 Work", "🧑‍💻 VPS"' in out
        assert "policy-path=sub.conf" not in out

    def test_group_becomes_empty_after_policy_path_stripped(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "#!include sub.conf\n"
            "[Proxy Group]\n"
            "Auto = smart, policy-path=sub.conf, interval=300\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        # smart → url-test direct hit, then cascade empties the group
        assert "# [V5+ cascade] Auto = url-test, interval=300" in out

    def test_http_policy_path_not_stripped(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "#!include sub.conf\n"
            "[Proxy Group]\n"
            "Mix = select, policy-path=https://example.com/a.conf, policy-path=sub.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "policy-path=https://example.com/a.conf" in out
        assert "policy-path=sub.conf" not in out


# --- T28: Cross-file cascade — #!include → abandoned ---

class TestCrossFileInclude:
    def test_abandoned_include_entry_removed(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        other = tmp_path / "other.conf"
        other.write_text(
            "[Proxy]\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include sub.conf, other.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include other-v4.conf" in out
        assert (tmp_path / "v4" / "other-v4.conf").exists()
        assert "sub.conf" not in out

    def test_sole_abandoned_include_commented(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[General]\nloglevel = notify\n"
            "[Proxy]\n"
            "#!include sub.conf\n"
            "LOCAL = ss, 9.9.9.9, 443, encrypt-method=aes-256-gcm, password=pwd\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] #!include sub.conf" in out
        assert "LOCAL = ss" in out

    def test_mixed_include_partial_abandon(self, tmp_path):
        """sub1 abandoned (managed v5+), sub2 converted normally."""
        sub1 = tmp_path / "sub1.conf"
        sub1.write_text(
            "#!MANAGED-CONFIG https://x.com/sub1.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        sub2 = tmp_path / "sub2.conf"
        sub2.write_text(
            "[Proxy]\n"
            "SNELL = snell, 5.6.7.8, 443, psk=pwd, version=5\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include sub1.conf, sub2.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include sub2-v4.conf" in out
        assert "sub1.conf" not in out
        assert "sub1-v4.conf" not in out


# --- T29: End-to-end real-world scenario ---

class TestRealWorldCascade:
    def test_home_conf_with_abandoned_provider(self, tmp_path):
        """Realistic multi-file layout: managed profile + sub-files."""
        provider = tmp_path / "provider-managed.conf"
        provider.write_text(
            "#!MANAGED-CONFIG https://managed.example.com/api/v1/abc interval=43200 strict=true\n"
            "[Proxy]\n"
            "🇯🇵 日本 = anytls, jp.airport.example, 35000, password=pwd\n"
            "🇭🇰 香港 = trojan, hk.airport.example, 443, password=pwd\n"
            "🇺🇸 美国 = anytls, us.airport.example, 35000, password=pwd\n"
        )
        (tmp_path / "work-vps.dconf").write_text(
            "[Proxy]\n🇺🇸 VPS-US-SNELL = snell, vps.example.com, 20443, psk=pwd, version=5\n"
        )
        (tmp_path / "own-vps.dconf").write_text(
            "[Proxy]\n# commented out\n"
        )
        (tmp_path / "own-lab.dconf").write_text(
            "[Proxy]\n🏡 HomeNode = snell, home.x, 20161, psk=pwd, version=5\n"
        )

        home = tmp_path / "profile.conf"
        home.write_text(
            "[General]\n"
            "loglevel = notify\n"
            "proxy-test-url = http://cp.cloudflare.com/generate_204\n"
            "\n"
            "[Proxy]\n"
            "#!include provider-managed.conf, work-vps.dconf, own-vps.dconf, own-lab.dconf\n"
            "\n"
            "[Proxy Group]\n"
            '✈️ Proxy = select, "💼 Work", "♻️ Auto", "🧑‍💻 VPS", "🏡 Home", policy-path=provider-managed.conf\n'
            "♻️ Auto = smart, policy-path=provider-managed.conf, interval=300\n"
            '💼 Work = select, include-all-proxies=1\n'
            '🧑‍💻 VPS = select, include-all-proxies=1\n'
            '🏡 Home = select, include-all-proxies=1\n'
            "\n"
            "[Rule]\n"
            'DOMAIN-SUFFIX,example.com,"✈️ Proxy"\n'
            "FINAL,✈️ Proxy\n"
        )

        stats = ConversionStats()
        convert_file(str(home), stats, {str(home): None})

        # 1. provider-managed.conf abandoned — no -v4 file written
        assert not (tmp_path / "v4" / "provider-managed-v4.conf").exists()
        assert str(provider) in stats.abandoned_files

        # 2. profile-v4.conf produced
        home_v4 = tmp_path / "v4" / "profile-v4.conf"
        assert home_v4.exists()
        out = home_v4.read_text()

        # 3. Include line: provider removed, work/own-lab rewritten to -v4,
        #    own-vps kept (pure v4, no conversion)
        assert "provider-managed.conf" not in out
        assert "provider-managed-v4.conf" not in out
        assert "work-vps-v4.dconf" in out
        assert "own-lab-v4.dconf" in out
        assert "own-vps-v4.dconf" in out
        assert (tmp_path / "v4" / "own-vps-v4.dconf").exists()

        # 4. ✈️ Proxy lost policy-path, lost ♻️ Auto (cascaded), kept other 3
        assert '✈️ Proxy = select, "💼 Work", "🧑‍💻 VPS", "🏡 Home"' in out

        # 5. ♻️ Auto cascaded to empty → commented
        assert "# [V5+ cascade] ♻️ Auto = url-test, interval=300" in out

        # 6. Other Proxy Groups untouched
        assert '💼 Work = select, include-all-proxies=1' in out

        # 7. Rules unchanged (✈️ Proxy still exists)
        assert 'DOMAIN-SUFFIX,example.com,"✈️ Proxy"' in out
        assert "FINAL,✈️ Proxy" in out

        # 8. Sub-file work-vps-v4.dconf has Snell version downgraded
        assert (tmp_path / "v4" / "work-vps-v4.dconf").exists()
        work_out = (tmp_path / "v4" / "work-vps-v4.dconf").read_text()
        assert "version=4" in work_out
        assert "version=5" not in work_out

    def test_stale_provider_v4_detected_not_deleted(self, tmp_path):
        """If provider-v4 exists from a previous run, it's recorded in
        stats.stale_v4_files but NOT auto-deleted."""
        provider = tmp_path / "provider.conf"
        provider.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        (tmp_path / "v4").mkdir()
        stale = tmp_path / "v4" / "provider-v4.conf"
        stale.write_text("stale content")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include provider.conf\n")

        stats = ConversionStats()
        with patch("converter.send2trash") as mock_trash:
            convert_file(str(main), stats, {str(main): None})
            # send2trash called only for deprecated_files path, NOT for stale v4
            assert mock_trash.call_count == 0

        assert stale.exists()
        assert stale.read_text() == "stale content"
        assert str(stale) in stats.stale_v4_files
        assert str(provider) in stats.abandoned_files


# --- T30: Stats reporting ---

class TestStatsReporting:
    def test_cascade_count_tracked(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,foo.com,OnlyV5\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        # Exactly: JP commented (direct), OnlyV5 cascade, rule cascade
        assert stats.lines_commented == 3

    def test_abandoned_files_tracked(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include sub.conf\n")

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})

        assert len(stats.abandoned_files) == 1
        assert str(sub) in stats.abandoned_files


# --- T31: unquote() direct tests ---

class TestUnquote:
    def test_quoted_name(self):
        assert unquote('"Hello"') == "Hello"

    def test_unquoted_name(self):
        assert unquote("Hello") == "Hello"

    def test_empty_string(self):
        assert unquote("") == ""

    def test_single_quote_char(self):
        assert unquote('"') == '"'

    def test_empty_quotes(self):
        assert unquote('""') == ""

    def test_emoji_quoted(self):
        assert unquote('"✈️ Proxy"') == "✈️ Proxy"

    def test_only_opening_quote(self):
        assert unquote('"Hello') == '"Hello'

    def test_only_closing_quote(self):
        assert unquote('Hello"') == 'Hello"'


# --- T32: has_effective_members() direct tests ---

class TestHasEffectiveMembers:
    def test_explicit_member_alive(self):
        pgl = ProxyGroupLine("G", "select", ["HK", "JP"], [])
        assert has_effective_members(pgl, {"JP"}, set()) is True

    def test_all_members_deleted(self):
        pgl = ProxyGroupLine("G", "select", ["JP"], [])
        assert has_effective_members(pgl, {"JP"}, set()) is False

    def test_no_members_no_options(self):
        pgl = ProxyGroupLine("G", "select", [], [])
        assert has_effective_members(pgl, set(), set()) is False

    def test_include_all_proxies_1(self):
        pgl = ProxyGroupLine("G", "url-test", [], [("include-all-proxies", "1")])
        assert has_effective_members(pgl, set(), set()) is True

    def test_include_all_proxies_true(self):
        pgl = ProxyGroupLine("G", "url-test", [], [("include-all-proxies", "true")])
        assert has_effective_members(pgl, set(), set()) is True

    def test_include_all_proxies_0(self):
        pgl = ProxyGroupLine("G", "url-test", [], [("include-all-proxies", "0")])
        assert has_effective_members(pgl, set(), set()) is False

    def test_policy_path_http(self):
        pgl = ProxyGroupLine("G", "select", [], [("policy-path", "https://x.com/a.conf")])
        assert has_effective_members(pgl, set(), set()) is True

    def test_policy_path_local_not_abandoned(self):
        pgl = ProxyGroupLine("G", "select", [], [("policy-path", "sub.conf")])
        assert has_effective_members(pgl, set(), set()) is True

    def test_policy_path_local_abandoned(self):
        pgl = ProxyGroupLine("G", "select", [], [("policy-path", "sub.conf")])
        assert has_effective_members(pgl, set(), {"sub.conf"}) is False

    def test_mixed_abandoned_and_http_policy_paths(self):
        pgl = ProxyGroupLine("G", "select", [], [
            ("policy-path", "sub.conf"),
            ("policy-path", "https://x.com/a.conf"),
        ])
        assert has_effective_members(pgl, set(), {"sub.conf"}) is True

    def test_builtin_member_survives(self):
        """DIRECT/REJECT are never in deleted_names so they count as alive."""
        pgl = ProxyGroupLine("G", "select", ["DIRECT"], [])
        assert has_effective_members(pgl, set(), set()) is True

    def test_quoted_member_deleted(self):
        pgl = ProxyGroupLine("G", "select", ['"🇯🇵 JP"'], [])
        assert has_effective_members(pgl, {"🇯🇵 JP"}, set()) is False


# --- T33: _split_top_level_commas() direct tests ---

class TestSplitTopLevelCommas:
    def test_simple(self):
        assert _split_top_level_commas("a,b,c") == ["a", "b", "c"]

    def test_no_commas(self):
        assert _split_top_level_commas("abc") == ["abc"]

    def test_empty_string(self):
        assert _split_top_level_commas("") == [""]

    def test_nested_parens(self):
        result = _split_top_level_commas("AND,((a,b),(c,d)),DIRECT")
        assert result == ["AND", "((a,b),(c,d))", "DIRECT"]

    def test_deeply_nested(self):
        result = _split_top_level_commas("OR,((AND,((a,b),(c,d))),(e,f)),Proxy")
        assert result == ["OR", "((AND,((a,b),(c,d))),(e,f))", "Proxy"]

    def test_no_nesting(self):
        result = _split_top_level_commas("DOMAIN-SUFFIX,example.com,DIRECT")
        assert result == ["DOMAIN-SUFFIX", "example.com", "DIRECT"]


# --- T34: compute_sections() direct tests ---

class TestComputeSections:
    def test_basic_sections(self):
        lines = ["[General]", "a=b", "[Proxy]", "X=y"]
        assert compute_sections(lines) == ["General", "General", "Proxy", "Proxy"]

    def test_no_section_header(self):
        lines = ["a=b", "c=d"]
        assert compute_sections(lines) == [None, None]

    def test_with_default_section(self):
        lines = ["a=b", "c=d", "[Rule]", "x"]
        assert compute_sections(lines, default_section="Proxy") == [
            "Proxy", "Proxy", "Rule", "Rule",
        ]

    def test_consecutive_headers(self):
        lines = ["[General]", "[Proxy]", "[Rule]"]
        assert compute_sections(lines) == ["General", "Proxy", "Rule"]

    def test_empty_lines(self):
        lines = ["[General]", "", "a=b", ""]
        assert compute_sections(lines) == ["General", "General", "General", "General"]


# --- T35: Multi-level cascade (3+ levels) ---

class TestMultiLevelCascade:
    def test_three_level_group_cascade(self, tmp_path):
        """A→B→C: proxy deleted → group B empty → group C loses B → C empty."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Inner = select, JP\n"
            "Middle = select, Inner\n"
            "Outer = select, Middle\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] Inner = select" in out
        assert "# [V5+ cascade] Middle = select" in out
        assert "# [V5+ cascade] Outer = select" in out

    def test_four_level_cascade_with_survivor(self, tmp_path):
        """Deep chain but one group has a builtin member → survives."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "L1 = select, JP\n"
            "L2 = select, L1\n"
            "L3 = select, L2, DIRECT\n"
            "L4 = select, L3, HK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] L1 = select" in out
        assert "# [V5+ cascade] L2 = select" in out
        # L3 survives because DIRECT is a builtin
        assert "L3 = select, DIRECT" in out
        assert "# [V5+ cascade] L3" not in out
        # L4 keeps both L3 and HK
        assert "L4 = select, L3, HK" in out


# --- T36: FINAL rule cascade ---

class TestFinalRuleCascade:
    def test_final_rule_policy_cascade_deleted_blocks_broken_emit(self, tmp_path):
        """When cascading removes the sole FINAL rule, refuse to emit an
        unloadable v4 profile and report the missing FINAL explicitly."""
        from converter import Pipeline

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "\n"
            "[Rule]\n"
            "FINAL,OnlyV5\n"
        )
        stats = ConversionStats()
        pipeline = Pipeline(stats, {str(main): None})
        result = pipeline.run(str(main))
        assert result is None
        assert not (tmp_path / "v4" / "main-v4.conf").exists()
        assert any("FINAL" in e for e in stats.errors)
        root_lines = pipeline.files[str(main)].lines
        assert "# [V5+ cascade] OnlyV5 = select" in root_lines
        assert "# [V5+ cascade] FINAL,OnlyV5" in root_lines

    def test_final_rule_with_dns_failed_cascade(self, tmp_path):
        """FINAL,GroupName,dns-failed — trailing option must not confuse policy extraction."""
        from converter import Pipeline

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "\n"
            "[Rule]\n"
            "FINAL,OnlyV5,dns-failed\n"
        )
        stats = ConversionStats()
        pipeline = Pipeline(stats, {str(main): None})
        result = pipeline.run(str(main))
        assert result is None
        assert any("FINAL" in e for e in stats.errors)
        assert "# [V5+ cascade] FINAL,OnlyV5,dns-failed" in pipeline.files[str(main)].lines


# --- T37: Snell version regex boundary ---

class TestSnellVersionBoundary:
    def test_version_50_not_downgraded(self):
        """version=50 must NOT be matched by the \\b boundary; like any
        version above 5 it has no v4 equivalent and is disabled instead."""
        result = convert("""
            [Proxy]
            S1 = snell, x.com, 443, psk=pwd, version=50
        """)
        assert "version=50" in result
        assert "version=4" not in result
        assert result.splitlines()[1].startswith("# [V5+] S1 = snell")

    def test_version_5_end_of_line(self):
        """version=5 at the very end of the line."""
        result = convert("""
            [Proxy]
            S1 = snell, x.com, 443, psk=pwd, version=5
        """)
        assert "version=4" in result
        assert "version=5" not in result

    def test_snell_version5_and_shadow_tls3(self):
        """Both downgrades on a single proxy line."""
        result = convert("""
            [Proxy]
            S1 = snell, x.com, 443, psk=pwd, version=5, shadow-tls-version=3, shadow-tls-password=abc
        """)
        assert "version=4" in result
        assert "version=5" not in result
        assert "shadow-tls-version=2" in result
        assert "shadow-tls-version=3" not in result
        assert "shadow-tls-password=abc" in result


# --- T37b: Snell version=6+ has no v4 equivalent: disabled like anytls ---

class TestSnellVersion6:
    def test_version6_commented(self):
        stats = ConversionStats()
        result = convert("""
            [Proxy]
            S6 = snell, x.com, 443, psk=pwd, version=6
            S5 = snell, y.com, 443, psk=pwd, version=5
        """, stats=stats)
        lines = result.splitlines()
        assert lines[1] == "# [V5+] S6 = snell, x.com, 443, psk=pwd, version=6"
        assert lines[2] == "S5 = snell, y.com, 443, psk=pwd, version=4"
        assert stats.lines_commented == 1
        assert ("注释", "S6 (snell version=6)") in [(c[3], c[4]) for c in stats.changes]

    def test_version_7_also_commented(self):
        result = convert("""
            [Proxy]
            S7 = snell, x.com, 443, psk=pwd, version=7
        """)
        assert result.splitlines()[1].startswith("# [V5+] S7 = snell")

    def test_shadow_tls_version_not_mistaken_for_snell_version(self):
        result = convert("""
            [Proxy]
            S = snell, x.com, 443, psk=pwd, version=4, shadow-tls-version=6
        """)
        assert not result.splitlines()[1].startswith("#")

    def test_non_snell_version_param_ignored(self):
        result = convert("""
            [Proxy]
            T = trojan, x.com, 443, password=pwd, version=6
        """)
        assert not result.splitlines()[1].startswith("#")

    def test_cross_file_cascade(self, tmp_path):
        """A v6 node cascades exactly like an anytls node: removed from
        groups, emptied groups and their rules commented."""
        nodes = tmp_path / "nodes.dconf"
        nodes.write_text(
            "S6 = snell, 1.2.3.4, 443, psk=pwd, version=6\n"
            "S5 = snell, 5.6.7.8, 443, psk=pwd, version=5\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include nodes.dconf\n"
            "[Proxy Group]\n"
            "Mixed = select, S6, S5\n"
            "Only6 = select, S6\n"
            "[Rule]\n"
            "DOMAIN,a.com,Only6\n"
            "DOMAIN,b.com,Mixed\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        nodes_out = (tmp_path / "v4" / "nodes-v4.dconf").read_text().splitlines()
        assert nodes_out[0] == "# [V5+] S6 = snell, 1.2.3.4, 443, psk=pwd, version=6"
        assert nodes_out[1] == "S5 = snell, 5.6.7.8, 443, psk=pwd, version=4"
        main_out = (tmp_path / "v4" / "main-v4.conf").read_text().splitlines()
        assert "Mixed = select, S5" in main_out
        assert "# [V5+ cascade] Only6 = select" in main_out
        assert "# [V5+ cascade] DOMAIN,a.com,Only6" in main_out
        assert "DOMAIN,b.com,Mixed" in main_out

    def test_commented_version6_left_verbatim(self, tmp_path):
        """Already disabled by the user: no v4 rewrite, no extra tag."""
        nodes = tmp_path / "nodes.dconf"
        nodes.write_text(
            "# OFF = snell, 1.2.3.4, 443, psk=pwd, version=6\n"
            "LIVE = snell, 5.6.7.8, 443, psk=pwd, version=5\n"
        )
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include nodes.dconf\n")
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        out = (tmp_path / "v4" / "nodes-v4.dconf").read_text().splitlines()
        assert out[0] == "# OFF = snell, 1.2.3.4, 443, psk=pwd, version=6"
        assert out[1] == "LIVE = snell, 5.6.7.8, 443, psk=pwd, version=4"
        assert stats.lines_commented == 0


# --- T38: Proxy name extraction with special characters ---

class TestProxyNameExtraction:
    def test_password_with_equals(self):
        """Proxy password containing '=' must not break name extraction."""
        result = convert("""
            [Proxy]
            MyProxy = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password=abc=def=ghi
        """)
        # Should pass through unchanged (v4-compatible proxy)
        assert "MyProxy = ss" in result

    def test_proxy_name_with_spaces(self):
        result = convert("""
            [Proxy]
            My Proxy = trojan, 1.2.3.4, 443, password=pwd
        """)
        assert "My Proxy = trojan" in result

    def test_proxy_name_quoted_in_section(self):
        """Quoted proxy name with emoji — common in Chinese configs."""
        result = convert("""
            [Proxy]
            "🇯🇵 东京" = anytls, 1.2.3.4, 443, password=pwd
        """)
        assert '# [V5+] "🇯🇵 东京" = anytls' in result


# --- T39: convert_content with default_section (sub-file scenario) ---

class TestDefaultSection:
    def test_subfile_no_section_header_proxy(self):
        """Sub-file without [Proxy] header, default_section='Proxy'."""
        stats = ConversionStats()
        content = "HY2 = hysteria2, 1.2.3.4, 443, password=pwd\nT1 = trojan, 5.6.7.8, 443, password=pwd"
        result = convert_content(content, "/tmp", stats, {}, default_section="Proxy", filename="sub.conf")
        assert "# [V5+] HY2 = hysteria2" in result
        assert "T1 = trojan" in result
        assert stats.lines_commented == 1

    def test_subfile_no_section_header_default_none(self):
        """Sub-file without section header and no default → lines pass through untouched."""
        stats = ConversionStats()
        content = "HY2 = hysteria2, 1.2.3.4, 443, password=pwd"
        result = convert_content(content, "/tmp", stats, {}, default_section=None, filename="sub.conf")
        # No section → no transform applied
        assert result == content
        assert stats.lines_commented == 0

    def test_section_header_overrides_default(self):
        """Explicit [Rule] header should override default_section='Proxy'."""
        stats = ConversionStats()
        content = "[Rule]\nHOSTNAME-TYPE,IPv4,Proxy"
        result = convert_content(content, "/tmp", stats, {}, default_section="Proxy", filename="sub.conf")
        assert "# [V5+] HOSTNAME-TYPE" in result


# --- T40: Empty / whitespace-only files ---

class TestEmptyFile:
    def test_empty_string(self):
        stats = ConversionStats()
        result = convert_content("", "/tmp", stats, {})
        assert result == ""

    def test_whitespace_only(self):
        stats = ConversionStats()
        result = convert_content("   \n\n  ", "/tmp", stats, {})
        # Should pass through without crashing
        assert stats.lines_commented == 0

    def test_empty_file_convert_file(self, tmp_path):
        main = tmp_path / "empty.conf"
        main.write_text("")
        result = convert_file(str(main), ConversionStats(), {str(main): None})
        assert result is None
        assert not (tmp_path / "v4" / "empty-v4.conf").exists()


# --- T41: Group with only builtins (no deletions involved) ---

class TestBuiltinOnlyGroup:
    def test_group_all_builtins_untouched(self, tmp_path):
        """Group with only DIRECT/REJECT members and no deletions → completely untouched."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Block = select, REJECT, DIRECT\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        # Block has no deleted members → stays exactly as-is
        assert "Block = select, REJECT, DIRECT" in out
        assert "# [V5+ cascade]" not in out

    def test_group_builtins_plus_deleted(self, tmp_path):
        """Group with builtins + deleted proxy → builtins survive, group stays."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Mixed = select, REJECT, JP, DIRECT\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "Mixed = select, REJECT, DIRECT" in out
        assert "# [V5+ cascade] Mixed" not in out


# --- T42: Rule with quoted policy cascade ---

class TestRuleQuotedPolicyCascade:
    def test_quoted_policy_cascade_deleted(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            '"✈️ Fly" = select, JP\n'
            "\n"
            "[Rule]\n"
            'DOMAIN,foo.com,"✈️ Fly"\n'
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert '# [V5+ cascade] "✈️ Fly" = select' in out
        assert '# [V5+ cascade] DOMAIN,foo.com,"✈️ Fly"' in out


# --- T43: remove_proxy_params edge cases ---

class TestRemoveProxyParamsEdge:
    def test_param_at_end_of_line(self):
        line = "X = ss, 1.2.3.4, 8000, password=pwd, ecn=true"
        result, removed = remove_proxy_params(line, {"ecn"})
        assert result == "X = ss, 1.2.3.4, 8000, password=pwd"
        assert removed == ["ecn"]

    def test_param_with_quoted_value(self):
        line = 'X = ss, 1.2.3.4, 8000, password=pwd, port-hopping="5000-6000"'
        result, removed = remove_proxy_params(line, {"port-hopping"})
        assert "port-hopping" not in result
        assert removed == ["port-hopping"]

    def test_multiple_params_all_removed(self):
        line = 'X = tuic, 1.2.3.4, 443, token=pwd, port-hopping="5000-6000", port-hopping-interval=30, ecn=true'
        result, removed = remove_proxy_params(line, {"port-hopping", "port-hopping-interval", "ecn"})
        assert "port-hopping" not in result
        assert "ecn" not in result
        assert "token=pwd" in result
        assert len(removed) == 3


# --- T44: extract_rule_policy edge cases ---

class TestExtractRulePolicyEdge:
    def test_not_compound_rule(self):
        assert extract_rule_policy(
            "NOT,((DOMAIN-SUFFIX,example.com)),DIRECT"
        ) == "DIRECT"

    def test_multiple_trailing_options(self):
        assert extract_rule_policy(
            "IP-CIDR,1.2.3.4/32,Proxy,no-resolve,force-remote-dns"
        ) == "Proxy"

    def test_final_single_arg(self):
        """FINAL with just one policy, no trailing options."""
        assert extract_rule_policy("FINAL,Proxy") == "Proxy"

    def test_rule_set_with_trailing(self):
        assert extract_rule_policy(
            "RULE-SET,https://x.com/list.list,Proxy,no-resolve"
        ) == "Proxy"


# --- T45: Unknown section passthrough ---

class TestUnknownSection:
    def test_mitm_section_untouched(self):
        result = convert("""
            [MITM]
            hostname = *.example.com
            h2 = true
        """)
        assert "hostname = *.example.com" in result
        assert "h2 = true" in result
        assert "# [V5+]" not in result

    def test_header_rewrite_section_untouched(self):
        result = convert("""
            [Header Rewrite]
            ^https://example.com header-replace User-Agent test
        """)
        assert "header-replace" in result
        assert "# [V5+]" not in result

    def test_lines_before_any_section(self):
        """Lines before any section header pass through untouched."""
        result = convert("""
            # This is a comment at the top
            some-line = value
        """)
        assert "# This is a comment at the top" in result
        assert "some-line = value" in result


# --- T46: Consecutive v5+ sections ---

class TestConsecutiveV5Sections:
    def test_two_v5_sections_back_to_back(self):
        result = convert("""
            [Port Forwarding]
            0.0.0.0:6841 localhost:3306

            [Body Rewrite]
            http-response ^https://api.example.com jq '.data'

            [General]
            loglevel = notify
        """)
        assert "# [V5+] [Port Forwarding]" in result
        assert "# [V5+] 0.0.0.0:6841" in result
        assert "# [V5+] [Body Rewrite]" in result
        assert "# [V5+] http-response" in result
        # General section should be normal
        assert "loglevel = notify" in result
        assert result.count("# [V5+]") == 4


# --- T47: Cross-file cascade with multiple abandoned files ---

class TestMultipleAbandonedFiles:
    def test_two_abandoned_subfiles(self, tmp_path):
        """Two managed sub-files both abandoned; parent cleans up both."""
        sub1 = tmp_path / "sub1.conf"
        sub1.write_text(
            "#!MANAGED-CONFIG https://x.com/sub1.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        sub2 = tmp_path / "sub2.conf"
        sub2.write_text(
            "#!MANAGED-CONFIG https://x.com/sub2.conf interval=3600\n"
            "[Proxy]\n"
            "US = hysteria2, 5.6.7.8, 443, password=pwd\n"
        )
        other = tmp_path / "other.conf"
        other.write_text("HK = trojan, 9.9.9.9, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include sub1.conf, sub2.conf, other.conf\n"
            "\n"
            "[Proxy Group]\n"
            "All = select, JP, US, HK\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()

        assert str(sub1) in stats.abandoned_files
        assert str(sub2) in stats.abandoned_files
        assert "#!include other-v4.conf" in out
        assert (tmp_path / "v4" / "other-v4.conf").exists()
        assert "sub1" not in out
        assert "sub2" not in out
        assert "All = select, HK" in out


# --- T48: Cascade with rules referencing directly deleted proxy ---

class TestRuleDirectProxyCascade:
    def test_rule_references_deleted_proxy_directly(self, tmp_path):
        """Rule policy is a proxy name (not a group) that got commented."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,fast.com,JP\n"
            "DOMAIN,slow.com,HK\n"
            "FINAL,HK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] DOMAIN,fast.com,JP" in out
        assert "DOMAIN,slow.com,HK" in out
        assert "FINAL,HK" in out


# --- T49: _preserve_indent edge cases ---

class TestPreserveIndent:
    def test_no_indent(self):
        from converter import _preserve_indent
        assert _preserve_indent("hello", "world") == "world"

    def test_spaces_indent(self):
        from converter import _preserve_indent
        assert _preserve_indent("    hello", "world") == "    world"

    def test_tab_indent(self):
        from converter import _preserve_indent
        assert _preserve_indent("\thello", "world") == "\tworld"

    def test_empty_original(self):
        from converter import _preserve_indent
        assert _preserve_indent("", "world") == "world"


# --- T50: Trailing newline preservation ---

class TestTrailingNewline:
    def test_content_with_trailing_newline(self):
        stats = ConversionStats()
        content = "[General]\nudp-priority = true\n"
        result = convert_content(content, "/tmp", stats, {})
        assert result.endswith("\n")

    def test_content_without_trailing_newline(self):
        stats = ConversionStats()
        content = "[General]\nudp-priority = true"
        result = convert_content(content, "/tmp", stats, {})
        assert not result.endswith("\n")


# --- T51: Cross-file direct-hit cascade between non-abandoned files ---

class TestCrossFileDirectHitCascade:
    def test_proxy_deleted_in_file_a_cascades_to_group_in_file_b(self, tmp_path):
        """Proxy commented in main.conf must cascade into groups defined in
        an included sub-file that references it by name."""
        sub = tmp_path / "groups.dconf"
        sub.write_text(
            "[Proxy Group]\n"
            "Fast = select, JP, HK\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "#!include groups.dconf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        main_out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+] JP = anytls" in main_out
        # The parent must reference the root-scoped -v4 copy of the cascade-modified sub
        scoped_subs = list((tmp_path / "v4").glob("main-groups-*-v4.dconf"))
        assert len(scoped_subs) == 1
        assert f"#!include {scoped_subs[0].name}" in main_out
        # The group is in the scoped subfile — JP must be removed from it
        sub_out = scoped_subs[0].read_text()
        assert "Fast = select, HK" in sub_out
        assert "JP" not in sub_out

    def test_deleted_proxy_cascades_empty_group_in_subfile(self, tmp_path):
        """If cascading empties a group in a sub-file, that group gets tagged."""
        sub = tmp_path / "groups.dconf"
        sub.write_text(
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "#!include groups.dconf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        scoped_subs = list((tmp_path / "v4").glob("main-groups-*-v4.dconf"))
        assert len(scoped_subs) == 1
        sub_out = scoped_subs[0].read_text()
        assert "# [V5+ cascade] OnlyV5 = select" in sub_out


# --- T52: Indented #!include handling ---

class TestIndentedInclude:
    def test_indented_include_still_parsed(self, tmp_path):
        """#!include with leading whitespace must still be processed."""
        sub = tmp_path / "sub.conf"
        sub.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n  #!include sub.conf\n")

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "sub-v4.conf" in out
        assert (tmp_path / "v4" / "sub-v4.conf").exists()


# --- T53: include-other-group as a member source (N4) ---

class TestIncludeOtherGroup:
    def test_group_with_include_other_group_survives(self, tmp_path):
        """A group whose remaining supply is include-other-group=<alive> must not be cascade-commented."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "HY = hysteria2, 1.2.3.4, 443, password=pwd\n"
            "OK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Alive = select, OK\n"
            "Combo = url-test, HY, include-other-group=Alive\n"
            "\n"
            "[Rule]\n"
            "FINAL,Combo\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "Combo = url-test, include-other-group=Alive" in out
        assert "# [V5+ cascade] Combo" not in out
        assert "FINAL,Combo" in out
        assert "# [V5+ cascade] FINAL,Combo" not in out

    def test_dead_include_other_group_removed_and_group_cascades(self, tmp_path):
        """include-other-group pointing at a cascade-deleted group is itself dead supply."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "HY = hysteria2, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, HY\n"
            "Wrap = select, include-other-group=OnlyV5\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] OnlyV5 = select" in out
        assert "# [V5+ cascade] Wrap = select" in out

    def test_has_effective_members_include_other_group(self):
        pgl = ProxyGroupLine("G", "select", [], [("include-other-group", "Alive")])
        assert has_effective_members(pgl, set(), set()) is True
        assert has_effective_members(pgl, {"Alive"}, set()) is False


# --- T54: v5+ rule types inside compound rules (N5) ---

class TestCompoundRuleV5Types:
    def test_domain_wildcard_inside_and_commented(self):
        result = convert("""
            [Rule]
            AND,((DOMAIN-WILDCARD,*bar*),(DEST-PORT,443)),DIRECT
        """)
        assert "# [V5+] AND,((DOMAIN-WILDCARD,*bar*),(DEST-PORT,443)),DIRECT" in result

    def test_hostname_type_inside_or_commented(self):
        result = convert("""
            [Rule]
            OR,((HOSTNAME-TYPE,IPv4),(DOMAIN,a.com)),Proxy
        """)
        assert "# [V5+] OR,((HOSTNAME-TYPE,IPv4),(DOMAIN,a.com)),Proxy" in result

    def test_plain_compound_rule_untouched(self):
        result = convert("""
            [Rule]
            AND,((DOMAIN-SUFFIX,example.com),(DEST-PORT,443)),DIRECT
        """)
        assert "# [V5+]" not in result


# --- T55: trailing blank line serialization (N6) ---

class TestTrailingBlankLine:
    def test_pure_v4_with_trailing_blank_line_not_converted(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\nOK = trojan, 1.2.3.4, 443, password=x\n\n")
        result = convert_file(str(main), ConversionStats(), {str(main): None})
        assert result is None
        assert not (tmp_path / "v4" / "main-v4.conf").exists()

    def test_changed_file_keeps_trailing_blank_line(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\nHY = hysteria2, 1.2.3.4, 443, password=x\n\n")
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert out.endswith("\n\n")


# --- T56: quoted names containing commas (N11) ---

class TestQuotedCommaNames:
    def test_parse_group_member_with_comma(self):
        pgl = parse_proxy_group_line('G = select, "HK, Fast", Direct')
        assert pgl.members == ['"HK, Fast"', "Direct"]

    def test_roundtrip_quoted_comma_member(self):
        line = 'G = select, "HK, Fast", DIRECT'
        assert format_proxy_group_line(parse_proxy_group_line(line)) == line

    def test_rule_policy_with_comma(self):
        assert extract_rule_policy('DOMAIN,example.com,"HK, Fast"') == '"HK, Fast"'

    def test_cascade_deletes_quoted_comma_member(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            '"HK, Fast" = hysteria2, 1.2.3.4, 443, password=x\n'
            "OK = trojan, 5.6.7.8, 443, password=x\n"
            "\n"
            "[Proxy Group]\n"
            'G = select, "HK, Fast", OK\n'
            "\n"
            "[Rule]\n"
            'DOMAIN,example.com,"HK, Fast"\n'
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "G = select, OK" in out
        assert '# [V5+ cascade] DOMAIN,example.com,"HK, Fast"' in out


# --- T57: proxy names containing '#' (N12) ---

class TestHashInProxyName:
    def test_extract_type_with_hash_in_name(self):
        assert extract_proxy_type("Node #1 = hysteria2, host, 443, password=x") == "hysteria2"

    def test_commented_line_still_returns_none(self):
        assert extract_proxy_type("# US = hysteria2, 1.2.3.4, 443") is None

    def test_v5_proxy_with_hash_name_commented(self):
        result = convert("""
            [Proxy]
            Node #1 = hysteria2, host, 443, password=x
        """)
        assert "# [V5+] Node #1 = hysteria2" in result


# --- T58: commented v5+ section headers keep section attribution (K9) ---

class TestCommentedSectionAttribution:
    def test_compute_sections_recognizes_commented_v5_header(self):
        lines = ["[Proxy]", "OK = trojan, 1.2.3.4, 443", "# [V5+] [Port Forwarding]", "# [V5+] OK = tcp, 0.0.0.0:8080"]
        assert compute_sections(lines) == ["Proxy", "Proxy", "Port Forwarding", "Port Forwarding"]

    def test_pf_body_name_collision_does_not_cascade(self, tmp_path):
        """A [Port Forwarding] body line whose LHS collides with a live proxy name
        must not poison deleted_names."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "OK = trojan, 1.2.3.4, 443, password=x\n"
            "\n"
            "[Port Forwarding]\n"
            "OK = tcp, 0.0.0.0:8080, 1.2.3.4:80\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, OK\n"
            "\n"
            "[Rule]\n"
            "FINAL,G\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "G = select, OK" in out
        assert "# [V5+ cascade]" not in out
        assert "FINAL,G" in out


# --- T59: extract_rule_policy trailing options coverage (N31) ---

class TestRuleTrailingOptionsCoverage:
    def test_extended_matching(self):
        assert extract_rule_policy("DOMAIN,x.com,MyGroup,extended-matching") == "MyGroup"

    def test_pre_matching(self):
        assert extract_rule_policy("DOMAIN,x.com,MyGroup,pre-matching") == "MyGroup"


# --- T60: pre-existing deprecated backup protected (K3) ---

class TestBackupCollision:
    def test_old_deprecated_backup_trashed_not_overwritten(self, tmp_path):
        """A kept -deprecated backup must go to trash before the new rename,
        never be silently overwritten."""
        main = tmp_path / "out.conf"
        main.write_text("[General]\nudp-priority = true\n")
        (tmp_path / "v4").mkdir()
        old_backup = tmp_path / "v4" / "out-v4-deprecated.conf"
        old_backup.write_text("precious old backup")
        stale = tmp_path / "v4" / "out-v4.conf"
        stale.write_text("stale v4")

        with patch("converter.send2trash") as mock_trash:
            convert_file(str(main), ConversionStats(), {str(main): None})
            assert mock_trash.call_count == 1
            assert mock_trash.call_args[0][0] == str(old_backup)
        # new backup holds the stale v4 content
        assert old_backup.read_text() == "stale v4"


# --- T61: UTF-8 BOM handling (K4) ---

class TestBomHandling:
    def test_bom_managed_config_abandoned(self, tmp_path):
        main = tmp_path / "sub.conf"
        main.write_bytes(
            "﻿#!MANAGED-CONFIG https://x.com/a.conf interval=3600\n"
            "[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n".encode("utf-8")
        )
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})
        assert result is None
        assert str(main) in stats.abandoned_files
        assert not (tmp_path / "v4" / "sub-v4.conf").exists()

    def test_bom_section_header_recognized(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_bytes(
            "﻿[Proxy]\nHY = hysteria2, 1.2.3.4, 443, password=pwd\n".encode("utf-8")
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+] HY = hysteria2" in out
        assert "﻿" not in out


# --- T62: old-layout stale -v4 detection (N7) ---

class TestOldLayoutStaleV4:
    def test_old_layout_stale_detected_on_abandon(self, tmp_path):
        main = tmp_path / "provider.conf"
        main.write_text(
            "#!MANAGED-CONFIG https://x.com/a.conf interval=3600\n"
            "[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        old_stale = tmp_path / "provider-v4.conf"  # pre-v4/-subdir layout
        old_stale.write_text("stale content")

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(old_stale) in stats.stale_v4_files
        assert old_stale.exists()  # never auto-deleted


# --- T63: deprecated prompt answer handling (N13 / K7 / N28) ---

class TestDeprecatedPrompt:
    def _setup(self, tmp_path):
        main_conf = tmp_path / "out.conf"
        main_conf.write_text("[General]\nudp-priority = true\n")
        (tmp_path / "v4").mkdir()
        (tmp_path / "v4" / "out-v4.conf").write_text("old content")
        return main_conf

    def _run_main(self, monkeypatch, main_conf, answer_fn):
        import types
        from converter import main as converter_main
        monkeypatch.setattr("sys.argv", ["converter.py", str(main_conf)])
        monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
        monkeypatch.setattr("builtins.input", answer_fn)
        with patch("converter.send2trash") as mock_trash:
            converter_main()
        return mock_trash

    def test_no_keeps_files(self, tmp_path, monkeypatch):
        """'no' must be treated as keep, not as consent."""
        main_conf = self._setup(tmp_path)
        mock_trash = self._run_main(monkeypatch, main_conf, lambda _: "no")
        assert mock_trash.call_count == 0
        assert (tmp_path / "v4" / "out-v4-deprecated.conf").exists()

    def test_enter_deletes_by_default(self, tmp_path, monkeypatch):
        main_conf = self._setup(tmp_path)
        mock_trash = self._run_main(monkeypatch, main_conf, lambda _: "")
        assert mock_trash.call_count == 1

    def test_n_keeps_files(self, tmp_path, monkeypatch):
        main_conf = self._setup(tmp_path)
        mock_trash = self._run_main(monkeypatch, main_conf, lambda _: "n")
        assert mock_trash.call_count == 0

    def test_eof_keeps_files_no_crash(self, tmp_path, monkeypatch):
        """Non-interactive stdin (cron/pipe) must not crash nor delete."""
        main_conf = self._setup(tmp_path)

        def raise_eof(_):
            raise EOFError

        mock_trash = self._run_main(monkeypatch, main_conf, raise_eof)
        assert mock_trash.call_count == 0
        assert (tmp_path / "v4" / "out-v4-deprecated.conf").exists()


# --- T64: unreadable / undecodable input (N14) ---

class TestUnreadableInput:
    def test_non_utf8_root_clean_error(self, tmp_path, capsys):
        main = tmp_path / "gbk.conf"
        main.write_bytes("[General]\n# 中文注释\n".encode("gbk"))
        with pytest.raises(SystemExit):
            convert_file(str(main), ConversionStats(), {str(main): None})
        assert "错误" in capsys.readouterr().err

    def test_unreadable_subfile_keeps_reference(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_bytes("SS = ss, 1.2.3.4, 443, encrypt-method=aes-256-gcm, password=x\n".encode("gbk") + b"\xff\xfe\xff")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\nHY = hysteria2, 1.2.3.4, 443, password=pwd\n#!include sub.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include sub.conf" in out  # original ref kept, no crash


# --- T65: directory input error message (N15) ---

class TestDirectoryInput:
    def test_directory_reports_not_a_file(self, tmp_path, capsys):
        with pytest.raises(SystemExit):
            convert_file(str(tmp_path), ConversionStats(), {})
        err = capsys.readouterr().err
        assert "目录" in err


# --- T66: cascade-only sub-file references rewritten (K1) ---

class TestCascadeOnlySubfileRefs:
    def test_include_ref_rewritten_for_cascade_only_change(self, tmp_path):
        """Sub-file whose ONLY change comes from cascade must still have the
        parent's #!include rewritten to its -v4 name."""
        sub = tmp_path / "groups.dconf"
        sub.write_text("[Proxy Group]\nFast = select, JP, HK\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "#!include groups.dconf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        main_out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include groups-v4.dconf" in main_out
        assert "#!include groups.dconf" not in main_out
        assert (tmp_path / "v4" / "groups-v4.dconf").exists()

    def test_policy_path_ref_rewritten_for_cascade_only_change(self, tmp_path):
        plist = tmp_path / "plist.conf"
        plist.write_text("[Proxy Group]\nInner = select, JP, DIRECT\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, DIRECT, policy-path=plist.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        main_out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "policy-path=plist-v4.conf" in main_out
        assert "policy-path=plist.conf" not in main_out
        assert (tmp_path / "v4" / "plist-v4.conf").exists()


# --- T67: managed file with cascade-only change abandoned (K2) ---

class TestManagedCascadeOnlyAbandon:
    def test_managed_cascade_only_change_is_abandoned(self, tmp_path):
        mgroups = tmp_path / "mgroups.conf"
        mgroups.write_text(
            "#!MANAGED-CONFIG https://x.com/mgroups.conf interval=3600\n"
            "[Proxy Group]\nFast = select, JP\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n#!include mgroups.conf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(mgroups) in stats.abandoned_files
        assert not (tmp_path / "v4" / "mgroups-v4.conf").exists()
        main_out = (tmp_path / "v4" / "main-v4.conf").read_text()
        # sole include entry pointed at the abandoned file → line cascade-commented
        assert "# [V5+ cascade] #!include mgroups.conf" in main_out


# --- T68: circular includes both rewritten (K5) ---

class TestCircularInclude:
    def test_mutual_includes_both_rewritten(self, tmp_path):
        a = tmp_path / "a.conf"
        a.write_text("[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n#!include b.conf\n")
        b = tmp_path / "b.conf"
        b.write_text("[Proxy]\nUS = hysteria2, 2.3.4.5, 443, password=pwd\n#!include a.conf\n")
        convert_file(str(a), ConversionStats(), {str(a): None})
        a_out = (tmp_path / "v4" / "a-v4.conf").read_text()
        b_out = (tmp_path / "v4" / "b-v4.conf").read_text()
        assert "#!include b-v4.conf" in a_out
        assert "#!include a-v4.conf" in b_out


# --- T69: orphan sub-file of abandoned managed config not emitted (N16) ---

class TestOrphanNotEmitted:
    def test_subfile_reachable_only_via_abandoned_not_emitted(self, tmp_path):
        inner = tmp_path / "inner.dconf"
        inner.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/managed.conf interval=3600\n"
            "[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n"
            "#!include inner.dconf\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\nOK = trojan, 9.9.9.9, 443, password=pwd\n#!include managed.conf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        assert not (tmp_path / "v4" / "inner-v4.dconf").exists()
        assert not (tmp_path / "v4" / "managed-v4.conf").exists()


# --- T70: URL include entry with colliding basename survives (N3 / N27) ---

class TestUrlIncludeBasenameCollision:
    def test_url_entry_survives_abandoned_local_collision(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\nHY = hysteria2, 9.9.9.9, 443, password=pwd\n"
            "#!include https://cdn.example.com/sub.conf, sub.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include https://cdn.example.com/sub.conf" in out
        assert "# [V5+ cascade] #!include" not in out


# --- T71: policy-path tolerant matching (K10) ---

class TestPolicyPathTolerantMatch:
    def test_space_around_equals_discovered(self, tmp_path):
        sub = tmp_path / "nodes.conf"
        sub.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")
        main = tmp_path / "main.conf"
        main.write_text("[Proxy Group]\nG = select, policy-path = nodes.conf\n")
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "policy-path=nodes-v4.conf" in out
        assert (tmp_path / "v4" / "nodes-v4.conf").exists()

    def test_filename_with_space_discovered(self, tmp_path):
        sub = tmp_path / "my nodes.conf"
        sub.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")
        main = tmp_path / "main.conf"
        main.write_text("[Proxy Group]\nG = select, policy-path=my nodes.conf\n")
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "policy-path=my nodes-v4.conf" in out
        assert (tmp_path / "v4" / "my nodes-v4.conf").exists()


# --- T72: reverse cross-file cascade (N26) ---

class TestReverseCrossFileCascade:
    def test_subfile_proxy_deleted_cleans_main_group(self, tmp_path):
        sub = tmp_path / "proxies.dconf"
        sub.write_text("JP = anytls, 1.2.3.4, 443, password=pwd\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "OK = trojan, 9.9.9.9, 443, password=pwd\n"
            "#!include proxies.dconf\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, JP, OK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "G = select, OK" in out


# --- T73: include under [Rule] section propagates section (N29) ---

class TestIncludeUnderRuleSection:
    def test_headerless_rule_subfile_converted(self, tmp_path):
        sub = tmp_path / "rules.dconf"
        sub.write_text("HOSTNAME-TYPE,IPv4,Proxy\nDOMAIN-SUFFIX,example.com,DIRECT\n")
        main = tmp_path / "main.conf"
        main.write_text("[Rule]\n#!include rules.dconf\n")
        convert_file(str(main), ConversionStats(), {str(main): None})
        sub_out = (tmp_path / "v4" / "rules-v4.dconf").read_text()
        assert "# [V5+] HOSTNAME-TYPE,IPv4,Proxy" in sub_out
        assert "DOMAIN-SUFFIX,example.com,DIRECT" in sub_out


# --- T74: second run idempotent after cascade (N30) ---

class TestCascadeIdempotency:
    def test_second_run_no_churn(self, tmp_path):
        sub = tmp_path / "groups.dconf"
        sub.write_text("[Proxy Group]\nFast = select, JP, HK\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "#!include groups.dconf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        stats2 = ConversionStats()
        convert_file(str(main), stats2, {str(main): None})
        assert stats2.files_processed == []
        assert stats2.deprecated_files == []
        assert not (tmp_path / "v4" / "main-v4-deprecated.conf").exists()
        assert not (tmp_path / "v4" / "groups-v4-deprecated.dconf").exists()


# --- T75: stats reconciled with emit decisions (K6 / K8 / N18) ---

class TestStatsReconciliation:
    def test_abandoned_file_edits_purged_from_stats(self, tmp_path):
        """Edits recorded for a later-abandoned managed file are discarded and
        must not appear in the summary nor inflate the counters."""
        sub = tmp_path / "work.dconf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/work.dconf interval=3600\n"
            "[Proxy]\n"
            "N1 = hysteria2, 1.2.3.4, 443, password=pwd\n"
            "N2 = snell, 5.6.7.8, 443, psk=pwd, version=5\n"
        )
        main = tmp_path / "main.conf"
        main.write_text("[General]\nudp-priority = true\n\n[Proxy]\n#!include work.dconf\n")
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        changed_files = {c[0] for c in stats.changes}
        assert "work.dconf" not in changed_files
        # counted: main's udp-priority (1) + cascade-commented include line (1)
        assert stats.lines_commented == 2
        assert stats.params_modified == 0

    def test_cascade_edits_recorded_in_changes(self, tmp_path):
        """Cascade cleanups must appear in the per-file change detail."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,foo.com,OnlyV5\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        actions = [(c[3], c[4]) for c in stats.changes]
        assert ("级联注释", "OnlyV5") in actions
        assert any(a == "级联注释" and "DOMAIN,foo.com,OnlyV5" in d for a, d in actions)

    def test_orphan_file_edits_purged(self, tmp_path):
        """Edits for an unreachable (orphan) sub-file are discarded too."""
        inner = tmp_path / "inner.dconf"
        inner.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n"
            "#!include inner.dconf\n"
        )
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\nOK = trojan, 9.9.9.9, 443, password=pwd\n#!include managed.conf\n")
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        changed_files = {c[0] for c in stats.changes}
        assert "inner.dconf" not in changed_files
        assert "managed.conf" not in changed_files


# --- T76: managed file dirtied only by reference rewrite is abandoned (R1F1) ---

class TestManagedRefRewriteAbandon:
    def test_managed_root_with_changed_sub_abandoned(self, tmp_path):
        """A managed config whose ONLY change would be an include rewrite
        (its sub-file needs conversion) must be abandoned, never emitted."""
        sub = tmp_path / "sub.dconf"
        sub.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\n#!include sub.dconf\n"
        )
        stats = ConversionStats()
        result = convert_file(str(managed), stats, {str(managed): None})
        assert result is None
        assert str(managed) in stats.abandoned_files
        assert not (tmp_path / "v4" / "managed-v4.conf").exists()
        # sub only reachable via the abandoned root → no orphan output
        assert not (tmp_path / "v4" / "sub-v4.dconf").exists()

    def test_parent_strips_ref_to_transitively_dirty_managed(self, tmp_path):
        """main → managed (clean itself) → sub (v5+): managed is abandoned,
        main's include entry for it is cleaned up."""
        sub = tmp_path / "sub.dconf"
        sub.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\n#!include sub.dconf\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\nOK = trojan, 9.9.9.9, 443, password=pwd\n#!include managed.conf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        assert not (tmp_path / "v4" / "managed-v4.conf").exists()
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] #!include managed.conf" in out


# --- T77: every line-level cascade mutation reaches per-file detail (R1F2) ---

class TestCascadeDetailCompleteness:
    def test_surviving_group_member_removal_recorded(self, tmp_path):
        sub = tmp_path / "groups.dconf"
        sub.write_text("[Proxy Group]\nFast = select, JP, HK\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "#!include groups.dconf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert any(
            c[0] == "groups.dconf" and c[3] == "级联移除成员" and "JP" in c[4]
            for c in stats.changes
        )

    def test_include_rewrite_recorded(self, tmp_path):
        sub = tmp_path / "groups.dconf"
        sub.write_text("[Proxy Group]\nFast = select, JP, HK\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "#!include groups.dconf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        scoped_subs = list((tmp_path / "v4").glob("main-groups-*-v4.dconf"))
        assert len(scoped_subs) == 1
        assert any(
            c[0] == "main.conf" and c[3] == "引用改写" and scoped_subs[0].name in c[4]
            for c in stats.changes
        )

    def test_partial_include_strip_recorded(self, tmp_path):
        sub1 = tmp_path / "sub1.conf"
        sub1.write_text(
            "#!MANAGED-CONFIG https://x.com/sub1.conf interval=3600\n"
            "[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        other = tmp_path / "other.conf"
        other.write_text("HK = trojan, 5.6.7.8, 443, password=pwd\n")
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include sub1.conf, other.conf\n")
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert any(
            c[0] == "main.conf" and c[3] == "移除 include 条目" and "sub1.conf" in c[4]
            for c in stats.changes
        )

    def test_partial_policy_path_strip_recorded(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\nJP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "#!include sub.conf\n"
            "[Proxy Group]\n"
            "G = select, DIRECT, policy-path=sub.conf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert any(
            c[0] == "main.conf" and c[3] == "移除 policy-path" and "sub.conf" in c[4]
            for c in stats.changes
        )


# --- T78: quoted member names never treated as policy-path (R1F3) ---

class TestQuotedMemberNotPolicyPath:
    def test_quoted_member_containing_policy_path_untouched(self, tmp_path):
        """A quoted member whose NAME contains 'policy-path=' must not be
        treated as a reference: no discovery, no rewrite, no output."""
        nodes = tmp_path / "nodes.conf"
        nodes.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            'G = select, "policy-path=nodes.conf, Fast", DIRECT\n'
        )
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})
        assert result is None
        assert not (tmp_path / "v4").exists()

    def test_real_policy_path_option_still_rewritten(self, tmp_path):
        nodes = tmp_path / "nodes.conf"
        nodes.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            'G = select, "policy-path=decoy.conf, Fast", policy-path=nodes.conf\n'
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "policy-path=nodes-v4.conf" in out
        assert '"policy-path=decoy.conf, Fast"' in out  # member name intact


# --- T79: non-TTY stdin never consents to deletion (R1F4) ---

class TestNonInteractiveStdin:
    def test_non_tty_blank_line_keeps_files(self, tmp_path, monkeypatch):
        """A pipe containing a blank line must NOT count as default-confirm."""
        import types
        main_conf = tmp_path / "out.conf"
        main_conf.write_text("[General]\nudp-priority = true\n")
        (tmp_path / "v4").mkdir()
        (tmp_path / "v4" / "out-v4.conf").write_text("old content")

        from converter import main as converter_main
        monkeypatch.setattr("sys.argv", ["converter.py", str(main_conf)])
        monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
        monkeypatch.setattr("builtins.input", lambda _: "")  # blank line in pipe
        with patch("converter.send2trash") as mock_trash:
            converter_main()
        assert mock_trash.call_count == 0
        assert (tmp_path / "v4" / "out-v4-deprecated.conf").exists()


# --- T80: unreachable subtree names enter the deletion closure (R2F1) ---

class TestUnreachableSubtreeNames:
    def test_orphan_subfile_names_cascade_deleted(self, tmp_path):
        """Names defined only in a sub-file that becomes unreachable (its sole
        parent is an abandoned managed config) must cascade-delete references
        in the emitted output."""
        inner = tmp_path / "inner.dconf"
        inner.write_text("X = trojan, 1.2.3.4, 443, password=pwd\n")
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 5.6.7.8, 443, password=pwd\n"
            "#!include inner.dconf\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "OK = trojan, 9.9.9.9, 443, password=pwd\n"
            "#!include managed.conf\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, X, OK\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,foo.com,X\n"
            "FINAL,G\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        assert not (tmp_path / "v4" / "inner-v4.dconf").exists()
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "G = select, OK" in out
        assert "# [V5+ cascade] DOMAIN,foo.com,X" in out
        assert "FINAL,G" in out  # G survives via OK

    def test_shared_subfile_directly_referenced_kept(self, tmp_path):
        """A sub-file reachable BOTH via an abandoned managed config AND via a
        direct root include stays live: its names must not be withdrawn."""
        inner = tmp_path / "inner.dconf"
        inner.write_text("X = trojan, 1.2.3.4, 443, password=pwd\n")
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 5.6.7.8, 443, password=pwd\n"
            "#!include inner.dconf\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "OK = trojan, 9.9.9.9, 443, password=pwd\n"
            "#!include managed.conf, inner.dconf\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, X, OK\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include inner-v4.dconf" in out   # kept, managed entry removed
        assert (tmp_path / "v4" / "inner-v4.dconf").exists()
        assert "G = select, X, OK" in out       # X alive — untouched
        assert "# [V5+ cascade]" not in out


# --- T74: Name collision between root config and abandoned managed config ---

class TestAbandonedNameCollision:
    def test_root_group_survives_same_name_in_abandoned_file(self, tmp_path):
        """A group name defined in BOTH the root config and an abandoned managed
        config still exists in the output — the root's own definition survives.
        Withdrawing the abandoned file's names must not kill references to the
        root's live, same-named group."""
        managed = tmp_path / "airport.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/a.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Proxy = select, JP\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include airport.conf\n"
            "OK = trojan, 9.9.9.9, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Proxy = select, OK, policy-path=airport.conf\n"
            'AI = select, "Proxy", OK\n'
            "\n"
            "[Rule]\n"
            'FINAL,"Proxy"\n'
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "Proxy = select, OK" in out        # policy-path stripped, group lives
        assert 'AI = select, "Proxy", OK' in out  # member NOT withdrawn
        assert 'FINAL,"Proxy"' in out             # rule NOT cascade-commented

    def test_root_proxy_survives_same_name_in_abandoned_file(self, tmp_path):
        """Same collision on the [Proxy] namespace: a node name defined in both
        the root and an abandoned managed config stays alive."""
        managed = tmp_path / "airport.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/a.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "KR = anytls, 5.6.7.8, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include airport.conf\n"
            "JP = trojan, 9.9.9.9, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, JP, KR\n"
            "\n"
            "[Rule]\n"
            "FINAL,JP\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "G = select, JP" in out   # KR withdrawn, JP kept
        assert "FINAL,JP" in out

    def test_policy_path_groups_are_not_live_definitions(self, tmp_path):
        """A file referenced only via policy-path contributes its [Proxy]
        section, NOT its [Proxy Group] definitions — Surge imports only the
        proxy section from such a file. Its group names must therefore not
        shield a same-named group that died with an abandoned file."""
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, JP\n"
        )
        nodes = tmp_path / "nodes.conf"
        nodes.write_text(
            "[Proxy]\n"
            "OKNODE = trojan, 8.8.8.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, OKNODE\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include managed.conf\n"
            "OK = trojan, 9.9.9.9, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Pool = select, policy-path=nodes.conf\n"
            "Wrap = select, G, DIRECT\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,example.com,G\n"
            "FINAL,Wrap\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "Wrap = select, DIRECT" in out
        assert "# [V5+ cascade] DOMAIN,example.com,G" in out
        assert "FINAL,Wrap" in out

    def test_included_file_groups_stay_live(self, tmp_path):
        """Counterpart: a file pulled in by [Proxy Group] #!include loads its
        [Proxy Group] definitions, so they shield the same name."""
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, JP\n"
        )
        nodes = tmp_path / "nodes.conf"
        nodes.write_text(
            "[Proxy]\n"
            "OKNODE = trojan, 8.8.8.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "G = select, OKNODE\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include managed.conf, nodes.conf\n"
            "OK = trojan, 9.9.9.9, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "#!include managed.conf, nodes.conf\n"
            "Wrap = select, G, DIRECT\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,example.com,G\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "Wrap = select, G, DIRECT" in out
        assert "DOMAIN,example.com,G" in out
        assert "# [V5+ cascade]" not in out.split("[Rule]")[1]

    def test_policy_path_chain_does_not_carry_names(self, tmp_path):
        """Surge takes only [Proxy] from a policy-path file, so that file's
        [Proxy Group] section — and any policy-path hanging off it — is never
        loaded. Names defined one level deeper must not count as live."""
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\n"
            "X = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        (tmp_path / "inner.conf").write_text(
            "[Proxy]\n"
            "X = trojan, 7.7.7.7, 443, password=pwd\n"
        )
        (tmp_path / "outer.conf").write_text(
            "[Proxy]\n"
            "OK = trojan, 8.8.8.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Hidden = select, policy-path=inner.conf\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include managed.conf\n"
            "BASE = trojan, 9.9.9.9, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Pool = select, policy-path=outer.conf\n"
            "Wrap = select, X, DIRECT\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,example.com,X\n"
            "FINAL,Wrap\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "Wrap = select, DIRECT" in out
        assert "# [V5+ cascade] DOMAIN,example.com,X" in out

    def test_deep_file_also_included_by_root_stays_live(self, tmp_path):
        """Counterpart: the same deep file ALSO pulled in by a root #!include
        is genuinely loaded, so its names keep shielding."""
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://x.com/m.conf interval=3600\n"
            "[Proxy]\n"
            "X = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        (tmp_path / "inner.conf").write_text(
            "[Proxy]\n"
            "X = trojan, 7.7.7.7, 443, password=pwd\n"
        )
        (tmp_path / "outer.conf").write_text(
            "[Proxy]\n"
            "OK = trojan, 8.8.8.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Hidden = select, policy-path=inner.conf\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include managed.conf, inner.conf\n"
            "BASE = trojan, 9.9.9.9, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Pool = select, policy-path=outer.conf\n"
            "Wrap = select, X, DIRECT\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,example.com,X\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        assert str(managed) in stats.abandoned_files
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "Wrap = select, X, DIRECT" in out
        assert "DOMAIN,example.com,X" in out


# --- T70: commented-out nodes get the same transforms as live ones ---

class TestCommentedProxyConversion:
    """A node the user commented out must still be v4-valid in the v4 copy,
    so uncommenting it there works. Comments never dirty a file by themselves."""

    def _run(self, tmp_path, proxy_lines, extra_live="LIVE = snell, example.com, 443, psk=test, version=5"):
        sub = tmp_path / "nodes.dconf"
        sub.write_text("\n".join(proxy_lines + [extra_live]) + "\n")
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include nodes.dconf\n")
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        out = (tmp_path / "v4" / "nodes-v4.dconf").read_text().splitlines()
        return out, stats

    def test_commented_snell_v5_becomes_v4(self, tmp_path):
        out, stats = self._run(tmp_path, [
            "# OFF = snell, example.com, 443, psk=test, version=5, reuse=true",
        ])
        assert out[0] == "# OFF = snell, example.com, 443, psk=test, version=4, reuse=true"
        assert out[1] == "LIVE = snell, example.com, 443, psk=test, version=4"
        assert any(c[3] == "version=5 → version=4" and c[4] == "OFF" for c in stats.changes)

    def test_prefix_variants_preserved(self, tmp_path):
        out, _ = self._run(tmp_path, [
            "#OFF1 = snell, example.com, 443, psk=test, version=5",
            "##  OFF2 = snell, example.com, 443, psk=test, version=5",
            "  # # OFF3 = snell, example.com, 443, psk=test, version=5",
            "// OFF4 = snell, example.com, 443, psk=test, version=5",
            "; OFF5 = snell, example.com, 443, psk=test, version=5",
        ])
        assert out[0] == "#OFF1 = snell, example.com, 443, psk=test, version=4"
        assert out[1] == "##  OFF2 = snell, example.com, 443, psk=test, version=4"
        assert out[2] == "  # # OFF3 = snell, example.com, 443, psk=test, version=4"
        assert out[3] == "// OFF4 = snell, example.com, 443, psk=test, version=4"
        assert out[4] == "; OFF5 = snell, example.com, 443, psk=test, version=4"

    def test_other_param_transforms_apply(self, tmp_path):
        out, _ = self._run(tmp_path, [
            "# T = trojan, example.com, 443, password=test, shadow-tls-version=3, ecn=true",
        ])
        assert out[0] == "# T = trojan, example.com, 443, password=test, shadow-tls-version=2"

    def test_free_form_comments_verbatim(self, tmp_path):
        notes = [
            "# 说明：snell version=5 要改成 version=4",
            "# shadow-tls-version=3, ecn=true 是 v5 参数",
            "# note = snell, see docs, version=5",
            "# X = snell, example.com, abc, version=5",
            "# X = snell, example.com, 443, psk test, version=5",
            "# X = wireguard, section-name=test, version=5",
            "#",
            "#!include other.dconf",
        ]
        out, _ = self._run(tmp_path, notes)
        assert out[:len(notes)] == notes

    def test_commented_v5plus_type_not_double_commented(self, tmp_path):
        lines = [
            "# AT = anytls, example.com, 443, password=test",
            "; HY = hysteria2, example.com, 443, password=test, port-hopping=1-2, ecn=true",
        ]
        out, stats = self._run(tmp_path, lines)
        assert out[:2] == lines
        assert stats.lines_commented == 0

    def test_live_nodes_unchanged_behavior(self, tmp_path):
        out, _ = self._run(tmp_path, [
            "AT = anytls, example.com, 443, password=test",
            "T = trojan, example.com, 443, password=test, ecn=true",
        ])
        assert out[0] == "# [V5+] AT = anytls, example.com, 443, password=test"
        assert out[1] == "T = trojan, example.com, 443, password=test"
        assert out[2] == "LIVE = snell, example.com, 443, psk=test, version=4"

    def test_comment_alone_does_not_trigger_output(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "# OFF = snell, example.com, 443, psk=test, version=5\n"
            "// OFF2 = snell, example.com, 443, psk=test, version=5\n"
            "ON = snell, example.com, 443, psk=test, version=4\n"
        )
        stats = ConversionStats()
        assert convert_file(str(main), stats, {str(main): None}) is None
        assert not (tmp_path / "v4").exists()
        assert stats.changes == []

    def test_comment_alone_does_not_abandon_managed(self, tmp_path):
        managed = tmp_path / "managed.conf"
        managed.write_text(
            "#!MANAGED-CONFIG https://example.com/m.conf interval=3600\n"
            "[Proxy]\n"
            "# OFF = snell, example.com, 443, psk=test, version=5\n"
            "ON = trojan, example.com, 443, password=test\n"
        )
        stats = ConversionStats()
        assert convert_file(str(managed), stats, {str(managed): None}) is None
        assert stats.abandoned_files == []


# --- T81: v5+ only rule options stripped, rule kept ---

class TestV5OnlyRuleOptions:
    def test_rule_set_extended_matching_removed(self):
        result = convert("""
            [Rule]
            RULE-SET,https://example.com/ad.list,REJECT-NO-DROP,extended-matching
        """)
        assert result.splitlines()[1] == "RULE-SET,https://example.com/ad.list,REJECT-NO-DROP"

    def test_pre_matching_removed(self):
        result = convert("""
            [Rule]
            DOMAIN-SET,https://example.com/ad.txt,REJECT,pre-matching
        """)
        assert result.splitlines()[1] == "DOMAIN-SET,https://example.com/ad.txt,REJECT"

    def test_both_removed(self):
        result = convert("""
            [Rule]
            DOMAIN-SUFFIX,example.com,REJECT,extended-matching,pre-matching
        """)
        assert result.splitlines()[1] == "DOMAIN-SUFFIX,example.com,REJECT"

    def test_other_options_kept(self):
        result = convert("""
            [Rule]
            RULE-SET,https://example.com/cn.list,DIRECT,extended-matching,no-resolve
            URL-REGEX,^https?://a\\.com/,Proxy,pre-matching,dns-failed
        """)
        lines = result.splitlines()
        assert lines[1] == "RULE-SET,https://example.com/cn.list,DIRECT,no-resolve"
        assert lines[2] == "URL-REGEX,^https?://a\\.com/,Proxy,dns-failed"

    def test_indent_preserved(self):
        result = convert("""
            [Rule]
            DOMAIN,a.com,DIRECT
              DOMAIN,b.com,DIRECT,extended-matching
        """)
        assert result.splitlines()[2] == "  DOMAIN,b.com,DIRECT"

    def test_criteria_value_not_touched(self):
        """Only options after the policy are stripped, never the matched value."""
        result = convert("""
            [Rule]
            DOMAIN-KEYWORD,pre-matching,DIRECT
        """)
        assert result.splitlines()[1] == "DOMAIN-KEYWORD,pre-matching,DIRECT"

    def test_commented_rule_unchanged(self):
        result = convert("""
            [Rule]
            # RULE-SET,https://example.com/ad.list,REJECT-NO-DROP,extended-matching
        """)
        assert result.splitlines()[1] == "# RULE-SET,https://example.com/ad.list,REJECT-NO-DROP,extended-matching"

    def test_plain_rules_unchanged(self):
        stats = ConversionStats()
        result = convert("""
            [Rule]
            RULE-SET,https://example.com/ad.list,REJECT-NO-DROP
            IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
            FINAL,Proxy,dns-failed
        """, stats=stats)
        assert result.splitlines()[1:] == [
            "RULE-SET,https://example.com/ad.list,REJECT-NO-DROP",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "FINAL,Proxy,dns-failed",
        ]
        assert stats.changes == []
        assert stats.params_modified == 0

    def test_change_recorded(self):
        stats = ConversionStats()
        convert("""
            [Rule]
            DOMAIN,a.com,DIRECT,extended-matching,pre-matching
        """, stats=stats, filename="test.conf")
        assert stats.params_modified == 2
        assert stats.lines_commented == 0
        assert [(c[1], c[2], c[3], c[4]) for c in stats.changes] == [
            (2, "Rule", "移除参数", "extended-matching (DOMAIN,a.com,DIRECT)"),
            (2, "Rule", "移除参数", "pre-matching (DOMAIN,a.com,DIRECT)"),
        ]


# --- T80: optional snell legacy override (extra v4-compatible server instance) ---

class TestSnellLegacyOverride:
    PSK = "FAKE-LEGACY-PSK-0000"
    HOST = "legacy.fake.example"
    V6 = "S6 = snell,  v6.fake.example , 6000 ,psk = FAKE-V6-PSK,  version = 6, tfo=true"

    def _run(self, tmp_path, nodes_text, legacy, nodes_name="nodes.dconf"):
        (tmp_path / nodes_name).write_text(nodes_text)
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            f"#!include {nodes_name}\n"
            "[Proxy Group]\n"
            "G6 = select, S6\n"
            "[Rule]\n"
            "DOMAIN,a.com,G6\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None}, snell_legacy=legacy)
        stem, ext = nodes_name.rsplit(".", 1)
        nodes_out = (tmp_path / "v4" / f"{stem}-v4.{ext}").read_text().splitlines()
        main_out = (tmp_path / "v4" / "main-v4.conf").read_text().splitlines()
        return nodes_out, main_out, stats

    def test_all_fields_replaced_rest_verbatim(self, tmp_path):
        legacy = {"nodes.dconf": {"server": self.HOST, "port": "7000", "psk": self.PSK}}
        nodes, main, stats = self._run(tmp_path, self.V6 + "\n", legacy)
        assert nodes[0] == (
            f"S6 = snell,  {self.HOST} , 7000 ,psk = {self.PSK},  version = 4, tfo=true")
        assert "G6 = select, S6" in main
        assert "DOMAIN,a.com,G6" in main
        assert stats.lines_commented == 0
        logged = repr(stats.changes)
        assert self.PSK not in logged and self.HOST not in logged

    @pytest.mark.parametrize("key, value, expected", [
        ("server", "legacy.fake.example",
         "S6 = snell,  legacy.fake.example , 6000 ,psk = FAKE-V6-PSK,  version = 4, tfo=true"),
        ("port", "7000",
         "S6 = snell,  v6.fake.example , 7000 ,psk = FAKE-V6-PSK,  version = 4, tfo=true"),
        ("psk", "FAKE-LEGACY-PSK-0000",
         "S6 = snell,  v6.fake.example , 6000 ,psk = FAKE-LEGACY-PSK-0000,  version = 4, tfo=true"),
    ])
    def test_single_field(self, tmp_path, key, value, expected):
        nodes, _, _ = self._run(tmp_path, self.V6 + "\n", {"nodes.dconf": {key: value}})
        assert nodes[0] == expected

    def test_partial_keys(self, tmp_path):
        legacy = {"nodes.dconf": {"port": "7000", "psk": self.PSK}}
        nodes, _, _ = self._run(tmp_path, self.V6 + "\n", legacy)
        assert nodes[0] == (
            f"S6 = snell,  v6.fake.example , 7000 ,psk = {self.PSK},  version = 4, tfo=true")

    def test_rewritten_line_gets_normal_v4_transforms(self, tmp_path):
        line = "S6 = snell, h.example, 6000, psk=x, version=6, shadow-tls-version=3, ecn=true\n"
        nodes, _, _ = self._run(tmp_path, line, {"nodes.dconf": {"port": "7000"}})
        assert nodes[0] == "S6 = snell, h.example, 7000, psk=x, version=4, shadow-tls-version=2"

    def test_unmatched_file_still_commented_and_cascades(self, tmp_path):
        legacy = {"other.dconf": {"port": "7000", "psk": self.PSK}}
        nodes, main, _ = self._run(tmp_path, self.V6 + "\n", legacy)
        assert nodes[0] == "# [V5+] " + self.V6
        assert any(l.startswith("# [V5+ cascade] G6 = select") for l in main)
        assert "# [V5+ cascade] DOMAIN,a.com,G6" in main

    def test_commented_v6_and_v5_and_other_types(self, tmp_path):
        text = (
            "# OFF = snell, 1.2.3.4, 6000, psk=FAKE-OFF, version=6\n"
            "S5 = snell, 5.6.7.8, 5000, psk=FAKE-V5, version=5\n"
            "HY = hysteria2, 9.9.9.9, 443, password=FAKE-HY\n"
            + self.V6 + "\n"
        )
        nodes, _, _ = self._run(tmp_path, text, {"nodes.dconf": {"port": "7000"}})
        assert nodes[0] == "# OFF = snell, 1.2.3.4, 6000, psk=FAKE-OFF, version=6"
        assert nodes[1] == "S5 = snell, 5.6.7.8, 5000, psk=FAKE-V5, version=4"
        assert nodes[2] == "# [V5+] HY = hysteria2, 9.9.9.9, 443, password=FAKE-HY"
        assert ", 7000 ," in nodes[3]

    def test_no_override_matches_default_behaviour(self, tmp_path):
        plain_dir, legacy_dir = tmp_path / "a", tmp_path / "b"
        plain_dir.mkdir(), legacy_dir.mkdir()
        assert (self._run(plain_dir, self.V6 + "\n", None)[:2]
                == self._run(legacy_dir, self.V6 + "\n", {})[:2])
        nodes, _, _ = self._run(plain_dir, self.V6 + "\n", None)
        assert nodes[0] == "# [V5+] " + self.V6


class TestSnellLegacyLoading:
    PSK = "FAKE-LEGACY-PSK-0000"

    def _write(self, path, text, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)
        return path

    def _main(self, monkeypatch, *argv):
        from converter import main as converter_main
        monkeypatch.setattr("sys.argv", ["converter.py", *argv])
        converter_main()

    def _profile(self, tmp_path):
        (tmp_path / "srv.dconf").write_text(
            "S6 = snell, v6.fake.example, 6000, psk=FAKE-V6-PSK, version=6\n")
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include srv.dconf\n")
        return main

    def test_parse_keeps_case_and_percent(self, tmp_path):
        from converter import load_snell_legacy
        f = self._write(tmp_path / "o.ini", "[Work.dconf]\nport = 7000\npsk = a%b\n")
        assert load_snell_legacy(str(f)) == {"Work.dconf": {"port": "7000", "psk": "a%b"}}

    @pytest.mark.parametrize("text", [
        f"[x.dconf]\npsk = {PSK}\npassword = {PSK}\n",          # unknown key
        "[x.dconf]\n",                                           # no keys
        f"[x.dconf]\nport = {PSK}\n",                            # non-numeric port
        f"[x.dconf]\npsk = {PSK},x\n",                           # comma breaks the line
        f"{PSK}\n",                                              # no section header
        f"[x.dconf]\n{PSK}\n",                                   # line without '='
    ])
    def test_invalid_file_exits_without_echoing_values(self, tmp_path, capsys, text):
        from converter import load_snell_legacy
        f = self._write(tmp_path / "o.ini", text)
        with pytest.raises(SystemExit) as exc:
            load_snell_legacy(str(f))
        captured = capsys.readouterr()
        assert self.PSK not in str(exc.value) + captured.out + captured.err

    def test_default_path_autoloaded(self, tmp_path, monkeypatch, capsys):
        xdg = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        self._write(xdg / "surge-config-converter" / "snell-legacy.ini",
                    f"[srv.dconf]\nserver = legacy.fake.example\npsk = {self.PSK}\n")
        main = self._profile(tmp_path)
        self._main(monkeypatch, str(main))
        out = (tmp_path / "v4" / "srv-v4.dconf").read_text()
        assert out == f"S6 = snell, legacy.fake.example, 6000, psk={self.PSK}, version=4\n"
        captured = capsys.readouterr()
        assert "snell-legacy.ini" in captured.out
        for secret in (self.PSK, "legacy.fake.example"):
            assert secret not in captured.out + captured.err

    def test_explicit_path_and_no_default(self, tmp_path, monkeypatch, capsys):
        f = self._write(tmp_path / "custom.ini", "[srv.dconf]\nport = 7000\n")
        main = self._profile(tmp_path)
        self._main(monkeypatch, "--snell-legacy", str(f), str(main))
        assert ", 7000," in (tmp_path / "v4" / "srv-v4.dconf").read_text()

    def test_no_file_feature_off(self, tmp_path, monkeypatch, capsys):
        main = self._profile(tmp_path)
        self._main(monkeypatch, str(main))
        out = (tmp_path / "v4" / "srv-v4.dconf").read_text()
        assert out.startswith("# [V5+] S6 = snell")
        assert "snell" not in capsys.readouterr().err

    @pytest.mark.parametrize("mode, warned", [(0o600, False), (0o400, False), (0o644, True)])
    def test_permission_warning(self, tmp_path, capsys, mode, warned):
        from converter import load_snell_legacy
        f = self._write(tmp_path / "o.ini", f"[x.dconf]\npsk = {self.PSK}\n", mode)
        load_snell_legacy(str(f))
        captured = capsys.readouterr()
        assert ("权限宽于 0600" in captured.err) is warned
        assert self.PSK not in captured.out + captured.err


# --- T22: New v5+/v6 protocols, block-quic param, Tailscale/wildcard sections, multi-group include-other-group ---

class TestV6ProtocolsAndParams:
    @pytest.mark.parametrize("line", [
        "MyTS = tailscale, section-name=myts",
        "SG-TUIC5 = tuic-v5, 1.2.3.4, 443, uuid=00000000-0000-0000-0000-000000000000, password=pwd",
        "US-VLESS = vless, 1.2.3.4, 443, username=00000000-0000-0000-0000-000000000000",
        "JP-MASQUE = masque, 1.2.3.4, 443, username=u, password=p",
        "EU-H2 = h2-connect, 1.2.3.4, 443, username=u, password=p",
    ])
    def test_new_v5plus_proxy_types_commented(self, line):
        result = convert(f"[Proxy]\n{line}\n")
        assert f"# [V5+] {line}" in result

    def test_block_quic_proxy_param_removed(self):
        result = convert("""
            [Proxy]
            US-SS = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password=pwd, block-quic=on, tfo=true
        """)
        assert "block-quic" not in result
        assert "tfo=true" in result
        assert not result.splitlines()[1].startswith("# [V5+]")


class TestTailscaleAndWildcardSections:
    def test_tailscale_named_and_wildcard_sections_commented(self):
        result = convert("""
            [Proxy]
            MyTS = tailscale, section-name=net1

            [Tailscale net1]
            interactive-login = true
            hostname = demo-node

            [Tailscale *]
            #!include tunnels.dconf

            [WireGuard *]
            #!include tunnels.dconf

            [Ruleset *]
            #!include rulesets.dconf
        """)
        lines = result.splitlines()
        assert "# [V5+] MyTS = tailscale, section-name=net1" in lines
        assert "# [V5+] [Tailscale net1]" in lines
        assert "# [V5+] interactive-login = true" in lines
        assert "# [V5+] [Tailscale *]" in lines
        assert "# [V5+] [WireGuard *]" in lines
        assert "# [V5+] [Ruleset *]" in lines
        assert lines.count("# [V5+] #!include tunnels.dconf") == 2

    def test_concrete_wireguard_section_preserved(self):
        result = convert("""
            [Proxy]
            OfficeWG = wireguard, section-name=office-wg

            [WireGuard office-wg]
            self-ip = 10.20.0.2
            mtu = 1280
        """)
        assert "[WireGuard office-wg]" in result
        assert "# [V5+]" not in result

    def test_detached_tunnel_dconf_end_to_end(self, tmp_path):
        (tmp_path / "tunnels.dconf").write_text(textwrap.dedent("""\
            [Proxy]
            DemoTS = tailscale, section-name=ABCD1234

            [Tailscale ABCD1234]
            interactive-login = true
        """))
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            #!include tunnels.dconf

            [Proxy Group]
            TS = select, include-all-proxies=1, policy-regex-filter=(?i)ts, hidden=true

            [WireGuard *]
            #!include tunnels.dconf

            [Tailscale *]
            #!include tunnels.dconf
        """))
        out = convert_file(str(root))
        assert out == str(tmp_path / "v4" / "profile-v4.conf")
        root_v4 = (tmp_path / "v4" / "profile-v4.conf").read_text()
        tunnels_v4 = (tmp_path / "v4" / "tunnels-v4.dconf").read_text()

        assert "#!include tunnels-v4.dconf" in root_v4
        assert "# [V5+] [WireGuard *]" in root_v4
        assert "# [V5+] [Tailscale *]" in root_v4
        # Commented #!include inside v5+ wildcard sections should NOT be rewritten
        assert root_v4.count("# [V5+] #!include tunnels.dconf") == 2
        assert "# [V5+] DemoTS = tailscale, section-name=ABCD1234" in tunnels_v4
        assert "# [V5+] [Tailscale ABCD1234]" in tunnels_v4
        assert "# [V5+] interactive-login = true" in tunnels_v4


class TestMultiGroupIncludeOtherGroupCascade:
    def test_partial_strip_keeps_surviving_groups(self, tmp_path):
        (tmp_path / "provider.conf").write_text(textwrap.dedent("""\
            #!MANAGED-CONFIG https://example.com/sub interval=86400
            [Proxy]
            P1 = anytls, 1.2.3.4, 443, password=pwd
        """))
        (tmp_path / "local-a.dconf").write_text("[Proxy]\nA1 = snell, 2.2.2.2, 8000, psk=a, version=4\n")
        (tmp_path / "local-b.dconf").write_text("[Proxy]\nB1 = snell, 3.3.3.3, 8000, psk=b, version=4\n")
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy Group]
            Provider = smart, policy-path=provider.conf
            GroupA = select, policy-path=local-a.dconf
            GroupB = select, policy-path=local-b.dconf
            AllNodes = select, include-other-group="Provider, GroupA, GroupB", hidden=true
            Downstream = select, include-other-group=AllNodes
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] Provider = url-test" in out
        assert 'AllNodes = select, include-other-group="GroupA, GroupB", hidden=true' in out
        assert "Downstream = select, include-other-group=AllNodes" in out

    def test_all_groups_deleted_cascades_group_and_downstream(self, tmp_path):
        (tmp_path / "p1.conf").write_text(
            "#!MANAGED-CONFIG https://example.com/1\n[Proxy]\nN1 = anytls, 1.1.1.1, 443, password=p\n"
        )
        (tmp_path / "p2.conf").write_text(
            "#!MANAGED-CONFIG https://example.com/2\n[Proxy]\nN2 = hysteria2, 2.2.2.2, 443, password=p\n"
        )
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy Group]
            G1 = select, policy-path=p1.conf
            G2 = select, policy-path=p2.conf
            Merged = select, include-other-group="G1, G2"
            Leaf = select, include-other-group=Merged

            [Rule]
            DOMAIN,example.com,Leaf
            FINAL,DIRECT
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] Merged = select" in out
        assert "# [V5+ cascade] Leaf = select" in out
        assert "# [V5+ cascade] DOMAIN,example.com,Leaf" in out

    def test_has_effective_members_multi_group(self):
        pgl = parse_proxy_group_line('All = select, include-other-group="G1, G2"')
        assert has_effective_members(pgl, {"G1"}, set()) is True
        assert has_effective_members(pgl, {"G1", "G2"}, set()) is False


# --- T81: Round 1 fixes — quoted proxy params, wildcard expansion, underlying-proxy, header comments, include-other-group syntax ---

class TestRemoveProxyParamsQuotedAndSpacing:
    def test_quoted_password_containing_param_not_truncated(self):
        line = 'US = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password="left, block-quic=right", tfo=true'
        result, removed = remove_proxy_params(line, V5PLUS_ONLY_PROXY_PARAMS)
        assert result == line
        assert removed == []

    def test_quoted_password_kept_while_real_spaced_param_removed(self):
        line = (
            'US = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, '
            'password="left, block-quic=right", block-quic = on, tfo=true # keep'
        )
        result, removed = remove_proxy_params(line, V5PLUS_ONLY_PROXY_PARAMS)
        assert result == (
            'US = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, '
            'password="left, block-quic=right", tfo=true # keep'
        )
        assert removed == ["block-quic"]

    def test_escaped_quote_in_password_and_inline_comment(self):
        line = 'US = ss, 1.2.3.4, 8000, password="a\\"b, block-quic=right", block-quic = auto // note'
        result, removed = remove_proxy_params(line, V5PLUS_ONLY_PROXY_PARAMS)
        assert result == 'US = ss, 1.2.3.4, 8000, password="a\\"b, block-quic=right" // note'
        assert removed == ["block-quic"]

    def test_hash_in_lhs_proxy_name_preserved(self):
        line = "Node #1 = ss, 1.2.3.4, 8000, password=pwd, block-quic = on"
        result, removed = remove_proxy_params(line, V5PLUS_ONLY_PROXY_PARAMS)
        assert result == "Node #1 = ss, 1.2.3.4, 8000, password=pwd"
        assert removed == ["block-quic"]

    def test_param_name_inside_inline_comment_untouched(self):
        line = "US = ss, 1.2.3.4, 8000, password=pwd # block-quic=on"
        result, removed = remove_proxy_params(line, V5PLUS_ONLY_PROXY_PARAMS)
        assert result == line
        assert removed == []

    def test_convert_preserves_quoted_password_and_removes_spaced_block_quic(self):
        result = convert("""
            [Proxy]
            US = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password="left, block-quic=right", block-quic = on, tfo=true
        """)
        assert (
            'US = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, '
            'password="left, block-quic=right", tfo=true'
        ) in result


class TestWildcardIncludePreservationAndCascade:
    WG_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    WG_PUB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

    def test_local_wireguard_and_ruleset_wildcards_preserved_end_to_end(self, tmp_path):
        (tmp_path / "tunnels.dconf").write_text(textwrap.dedent(f"""\
            [Proxy]
            OfficeWG = wireguard, section-name=office
            MyTS = tailscale, section-name=ts1

            [WireGuard office]
            private-key = {self.WG_KEY}
            self-ip = 10.20.0.2
            mtu = 1280
            peer = (public-key = {self.WG_PUB}, allowed-ips = "10.20.0.0/24", endpoint = 1.2.3.4:51820)

            [Tailscale ts1]
            interactive-login = true

            [Ruleset OfficeSites]
            DOMAIN-SUFFIX,corp.example
            DOMAIN-WILDCARD,*corp.example
            DOMAIN,cdn.corp.example,extended-matching
            IP-CIDR,10.20.0.0/24,no-resolve
        """))
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            #!include tunnels.dconf

            [WireGuard *]
            #!include tunnels.dconf

            [Tailscale *]
            #!include tunnels.dconf

            [Ruleset *]
            #!include tunnels.dconf

            [Rule]
            RULE-SET,OfficeSites,OfficeWG
            FINAL,DIRECT
        """))
        out = convert_file(str(root))
        assert out == str(tmp_path / "v4" / "profile-v4.conf")
        root_v4 = (tmp_path / "v4" / "profile-v4.conf").read_text()
        tunnels_v4 = (tmp_path / "v4" / "tunnels-v4.dconf").read_text()
        rs_files = list((tmp_path / "v4").glob("profile-OfficeSites-*-ruleset-v4.list"))
        assert len(rs_files) == 1
        rs_file = rs_files[0]

        # Wildcard headers are commented; concrete [WireGuard office] is expanded and rewritten
        assert "# [V5+] [WireGuard *]" in root_v4
        assert "[WireGuard office]\n#!include tunnels-v4.dconf" in root_v4
        assert "# [V5+] [Ruleset *]" in root_v4
        # OfficeWG survives in tunnels-v4.dconf; Tailscale & inline Ruleset are commented
        assert "\nOfficeWG = wireguard, section-name=office\n" in tunnels_v4
        assert "# [V5+] MyTS = tailscale, section-name=ts1" in tunnels_v4
        assert "# [V5+] [Ruleset OfficeSites]" in tunnels_v4
        # Inline ruleset materialized into root-scoped v4/*.list with v4 rule conversion applied
        rs_text = rs_file.read_text()
        assert "DOMAIN-SUFFIX,corp.example" in rs_text
        assert "# [V5+] DOMAIN-WILDCARD,*corp.example" in rs_text
        assert "DOMAIN,cdn.corp.example\n" in rs_text
        assert "extended-matching" not in rs_text
        assert "IP-CIDR,10.20.0.0/24,no-resolve" in rs_text
        # RULE-SET rewritten to exported .list file
        assert f"RULE-SET,{rs_file.name},OfficeWG" in root_v4

        # Second run is idempotent (no deprecated backup created)
        stats2 = ConversionStats()
        convert_file(str(root), stats2)
        assert stats2.deprecated_files == []

    def test_inline_ruleset_in_root_exported_and_unused_skipped(self, tmp_path):
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Ruleset UsedSet]
            DOMAIN-SUFFIX,used.example

            [Ruleset UnusedSet]
            DOMAIN-SUFFIX,unused.example

            [Rule]
            RULE-SET,UsedSet,DIRECT
            FINAL,DIRECT
        """))
        convert_file(str(root))
        root_v4 = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert "# [V5+] [Ruleset UsedSet]" in root_v4
        assert "# [V5+] [Ruleset UnusedSet]" in root_v4
        used_files = list((tmp_path / "v4").glob("profile-UsedSet-*-ruleset-v4.list"))
        assert len(used_files) == 1
        assert f"RULE-SET,{used_files[0].name},DIRECT" in root_v4
        assert used_files[0].read_text() == "DOMAIN-SUFFIX,used.example\n"
        assert list((tmp_path / "v4").glob("*UnusedSet*")) == []

    def test_unexpandable_remote_wildcards_cascade_dangling_wg_and_ruleset(self, tmp_path):
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent(f"""\
            [Proxy]
            RemoteWG = wireguard, section-name=remote-wg
            LocalWG = wireguard, section-name=local-wg

            [WireGuard local-wg]
            private-key = {self.WG_KEY}
            self-ip = 10.20.0.2
            mtu = 1280
            peer = (public-key = {self.WG_PUB}, allowed-ips = "10.20.0.0/24", endpoint = 1.2.3.4:51820)

            [WireGuard *]
            #!include https://example.com/wg.conf

            [Ruleset *]
            #!include https://example.com/rs.conf

            [Proxy Group]
            OnlyRemote = select, RemoteWG
            Both = select, RemoteWG, LocalWG

            [Rule]
            RULE-SET,RemoteSites,DIRECT
            RULE-SET,SYSTEM,DIRECT
            RULE-SET,LAN,DIRECT
            RULE-SET,https://example.com/ext.list,DIRECT
            DOMAIN,a.example,OnlyRemote
            FINAL,Both
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert "# [V5+ cascade] RemoteWG = wireguard, section-name=remote-wg" in out
        assert "\nLocalWG = wireguard, section-name=local-wg\n" in out
        assert "# [V5+ cascade] OnlyRemote = select" in out
        assert "Both = select, LocalWG" in out
        assert "# [V5+ cascade] RULE-SET,RemoteSites,DIRECT" in out
        assert "\nRULE-SET,SYSTEM,DIRECT\n" in out
        assert "\nRULE-SET,LAN,DIRECT\n" in out
        assert "\nRULE-SET,https://example.com/ext.list,DIRECT\n" in out
        assert "# [V5+ cascade] DOMAIN,a.example,OnlyRemote" in out
        assert "\nFINAL,Both\n" in out

    def test_managed_wildcard_target_abandoned_and_cascades(self, tmp_path):
        managed = tmp_path / "managed-tunnels.dconf"
        managed.write_text(textwrap.dedent(f"""\
            #!MANAGED-CONFIG https://example.com/tunnels.dconf interval=86400
            [WireGuard office]
            private-key = {self.WG_KEY}
            self-ip = 10.20.0.2
            mtu = 1280
            peer = (public-key = {self.WG_PUB}, allowed-ips = "10.20.0.0/24", endpoint = 1.2.3.4:51820)

            [Ruleset CorpSites]
            DOMAIN-SUFFIX,corp.example
        """))
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            OfficeWG = wireguard, section-name=office

            [WireGuard *]
            #!include managed-tunnels.dconf

            [Ruleset *]
            #!include managed-tunnels.dconf

            [Rule]
            RULE-SET,CorpSites,DIRECT
            DOMAIN,corp.example,OfficeWG
            FINAL,DIRECT
        """))
        stats = ConversionStats()
        convert_file(str(root), stats)
        out = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert str(managed) in stats.abandoned_files
        assert not (tmp_path / "v4" / "managed-tunnels-v4.dconf").exists()
        assert not (tmp_path / "v4" / "CorpSites-ruleset-v4.list").exists()
        assert "# [V5+ cascade] OfficeWG = wireguard, section-name=office" in out
        assert "# [V5+ cascade] RULE-SET,CorpSites,DIRECT" in out
        assert "# [V5+ cascade] DOMAIN,corp.example,OfficeWG" in out

    def test_wireguard_only_wildcard_target_still_discovered_and_emitted(self, tmp_path):
        (tmp_path / "wg-only.dconf").write_text(textwrap.dedent(f"""\
            [WireGuard office]
            private-key = {self.WG_KEY}
            self-ip = 10.20.0.2
            mtu = 1280
            peer = (public-key = {self.WG_PUB}, allowed-ips = "10.20.0.0/24", endpoint = 1.2.3.4:51820)
        """))
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            OfficeWG = wireguard, section-name=office

            [WireGuard *]
            #!include wg-only.dconf

            [Rule]
            FINAL,OfficeWG
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert "[WireGuard office]\n#!include wg-only-v4.dconf" in out
        assert (tmp_path / "v4" / "wg-only-v4.dconf").exists()
        assert "\nOfficeWG = wireguard, section-name=office\n" in out

    def test_proxy_include_alone_does_not_load_wireguard_section(self, tmp_path):
        """[Proxy] #!include loads only [Proxy]; if [WireGuard *] is unexpandable
        (remote URL), a [WireGuard office] sitting inside the [Proxy] include
        file does NOT satisfy OfficeWG."""
        (tmp_path / "tunnels.dconf").write_text(textwrap.dedent(f"""\
            [Proxy]
            OfficeWG = wireguard, section-name=office

            [WireGuard office]
            private-key = {self.WG_KEY}
            self-ip = 10.20.0.2
            mtu = 1280
            peer = (public-key = {self.WG_PUB}, allowed-ips = "10.20.0.0/24", endpoint = 1.2.3.4:51820)
        """))
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            #!include tunnels.dconf

            [WireGuard *]
            #!include https://example.com/wg.conf

            [Rule]
            DOMAIN,corp.example,OfficeWG
            FINAL,DIRECT
        """))
        convert_file(str(root))
        scoped_tunnels = list((tmp_path / "v4").glob("profile-tunnels-*-v4.dconf"))
        assert len(scoped_tunnels) == 1
        tunnels_v4 = scoped_tunnels[0].read_text()
        root_v4 = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert f"#!include {scoped_tunnels[0].name}" in root_v4
        assert "# [V5+ cascade] OfficeWG = wireguard, section-name=office" in tunnels_v4
        assert "# [V5+ cascade] DOMAIN,corp.example,OfficeWG" in root_v4

    def test_wildcard_headers_with_inline_comments_still_expand_and_export(self, tmp_path):
        (tmp_path / "tunnels.dconf").write_text(textwrap.dedent(f"""\
            [Proxy]
            OfficeWG = wireguard, section-name=office

            [WireGuard office] # tunnel body
            private-key = {self.WG_KEY}
            self-ip = 10.20.0.2
            mtu = 1280
            peer = (public-key = {self.WG_PUB}, allowed-ips = "10.20.0.0/24", endpoint = 1.2.3.4:51820)

            [Ruleset OfficeSites] // inline rules
            DOMAIN-SUFFIX,corp.example
        """))
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy] # main proxies
            #!include tunnels.dconf

            [WireGuard *] # expand wg
            #!include tunnels.dconf

            [Ruleset *] ; export rs
            #!include tunnels.dconf

            [Rule]
            RULE-SET,OfficeSites,OfficeWG
            FINAL,DIRECT
        """))
        convert_file(str(root))
        root_v4 = (tmp_path / "v4" / "profile-v4.conf").read_text()
        rs_files = list((tmp_path / "v4").glob("profile-OfficeSites-*-ruleset-v4.list"))
        assert len(rs_files) == 1
        assert "# [V5+] [WireGuard *] # expand wg" in root_v4
        assert "[WireGuard office]\n#!include tunnels-v4.dconf" in root_v4
        assert "# [V5+] [Ruleset *] ; export rs" in root_v4
        assert f"RULE-SET,{rs_files[0].name},OfficeWG" in root_v4


class TestUnderlyingProxyCascade:
    def test_single_and_multi_hop_underlying_proxy_cascade(self, tmp_path):
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            Entry = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            Mid = snell, 2.2.2.2, 8000, psk=a, version=4, underlying-proxy=Entry
            Exit = trojan, 3.3.3.3, 443, password=b, underlying-proxy = Mid # chain
            Safe = ss, 4.4.4.4, 8388, encrypt-method=aes-256-gcm, password="x, underlying-proxy=Entry"

            [Proxy Group]
            ChainOnly = select, Exit
            Mixed = select, Exit, Safe

            [Rule]
            DOMAIN,chain.example,ChainOnly
            DOMAIN,exit.example,Exit
            FINAL,Mixed
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+] Entry = vless" in out
        assert "# [V5+ cascade] Mid = snell" in out
        assert "# [V5+ cascade] Exit = trojan" in out
        assert "\nSafe = ss," in out
        assert "# [V5+ cascade] ChainOnly = select" in out
        assert "Mixed = select, Safe" in out
        assert "# [V5+ cascade] DOMAIN,chain.example,ChainOnly" in out
        assert "# [V5+ cascade] DOMAIN,exit.example,Exit" in out
        assert "\nFINAL,Mixed\n" in out

    def test_group_and_cross_file_underlying_proxy_cascade(self, tmp_path):
        (tmp_path / "entry.dconf").write_text(
            "[Proxy]\nEntry = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000\n"
        )
        (tmp_path / "exit.dconf").write_text(
            "[Proxy]\n"
            "ExitViaGroup = snell, 2.2.2.2, 8000, psk=a, version=4, underlying-proxy=EntryGroup\n"
            "OK = snell, 3.3.3.3, 8000, psk=b, version=4\n"
        )
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            #!include entry.dconf, exit.dconf

            [Proxy Group]
            EntryGroup = select, Entry
            ChainedGroup = select, OK, underlying-proxy=Entry

            [Rule]
            DOMAIN,a.example,ExitViaGroup
            DOMAIN,b.example,ChainedGroup
            FINAL,OK
        """))
        convert_file(str(root))
        main_v4 = (tmp_path / "v4" / "main-v4.conf").read_text()
        scoped_exit = list((tmp_path / "v4").glob("main-exit-*-v4.dconf"))
        assert len(scoped_exit) == 1
        exit_v4 = scoped_exit[0].read_text()
        assert f"#!include entry-v4.dconf, {scoped_exit[0].name}" in main_v4
        assert "# [V5+ cascade] EntryGroup = select" in main_v4
        assert "# [V5+ cascade] ChainedGroup = select, OK, underlying-proxy=Entry" in main_v4
        assert "# [V5+ cascade] ExitViaGroup = snell" in exit_v4
        assert "# [V5+ cascade] DOMAIN,a.example,ExitViaGroup" in main_v4
        assert "# [V5+ cascade] DOMAIN,b.example,ChainedGroup" in main_v4
        assert "\nFINAL,OK\n" in main_v4


class TestSectionHeaderInlineComments:
    def test_v5_named_and_wildcard_headers_with_inline_comments(self):
        result = convert("""
            [Proxy] # 代理列表
            MyTS = tailscale, section-name=office

            [Tailscale office] # 说明
            interactive-login = true

            [WireGuard *] ; note
            #!include tunnels.dconf

            [Ruleset *] // note
            #!include rulesets.dconf

            [Ruleset Custom] # inline ruleset
            DOMAIN-SUFFIX,a.example
        """)
        lines = result.splitlines()
        assert "[Proxy] # 代理列表" in lines
        assert "# [V5+] MyTS = tailscale, section-name=office" in lines
        assert "# [V5+] [Tailscale office] # 说明" in lines
        assert "# [V5+] interactive-login = true" in lines
        assert "# [V5+] [WireGuard *] ; note" in lines
        assert "# [V5+] [Ruleset *] // note" in lines
        assert "# [V5+] [Ruleset Custom] # inline ruleset" in lines
        assert "# [V5+] DOMAIN-SUFFIX,a.example" in lines

    def test_compute_sections_handles_inline_comments(self):
        lines = [
            "[Proxy] # proxies",
            "A = snell, 1.1.1.1, 8000, psk=x, version=4",
            "# [V5+] [Tailscale office] # 说明",
            "# [V5+] interactive-login = true",
            "[Rule] // rules",
            "FINAL,DIRECT",
        ]
        assert compute_sections(lines) == [
            "Proxy", "Proxy", "Tailscale office", "Tailscale office", "Rule", "Rule"
        ]

    def test_non_space_hash_after_bracket_not_header(self):
        from converter import parse_section_header
        assert parse_section_header("[Tailscale office]#not-comment") is None
        assert parse_section_header("[Tailscale office] # comment") == "Tailscale office"


class TestIncludeOtherGroupSyntaxAndComments:
    def test_inline_comment_full_cascade(self, tmp_path):
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            P1 = anytls, 1.1.1.1, 443, password=p
            P2 = hysteria2, 2.2.2.2, 443, password=p

            [Proxy Group]
            G1 = select, P1
            G2 = select, P2
            Merged = select, include-other-group="G1,G2" # 说明
            Leaf = select, include-other-group=Merged

            [Rule]
            DOMAIN,dead.example,Leaf
            FINAL,DIRECT
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] Merged = select # 说明" in out
        assert "# [V5+ cascade] Leaf = select" in out
        assert "# [V5+ cascade] DOMAIN,dead.example,Leaf" in out
        assert "\nFINAL,DIRECT\n" in out

    def test_inline_comment_partial_strip_preserves_comment(self, tmp_path):
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            P1 = anytls, 1.1.1.1, 443, password=p
            OK = snell, 2.2.2.2, 8000, psk=a, version=4

            [Proxy Group]
            G1 = select, P1
            G2 = select, OK
            Merged = select, include-other-group="G1,G2" # 说明

            [Rule]
            FINAL,Merged
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert 'Merged = select, include-other-group="G2" # 说明' in out
        assert "\nFINAL,Merged\n" in out

    def test_escaped_backslash_group_name_matched_and_reencoded_for_v4(self, tmp_path):
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            P1 = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            OK = snell, 2.2.2.2, 8000, psk=a, version=4

            [Proxy Group]
            Gone\\Team = select, P1
            Keep\\Team = select, OK
            G2 = select, OK
            DropGone = select, include-other-group="Gone\\\\Team,G2" # drop escaped
            KeepEsc = select, include-other-group="Gone\\\\Team,Keep\\\\Team"
            BothKeep = select, include-other-group="Keep\\\\Team,G2"
            AllGone = select, include-other-group="Gone\\\\Team" // dead

            [Rule]
            DOMAIN,dead.example,AllGone
            FINAL,DropGone
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] Gone\\Team = select" in out
        assert 'DropGone = select, include-other-group="G2" # drop escaped' in out
        # v4-readable: single backslash-bearing name emitted unquoted (no v5.21+ \\ escape)
        assert "KeepEsc = select, include-other-group=Keep\\Team\n" in out
        # v4-readable multi-group: literal single backslash without v5.21+ \\ escape
        assert 'BothKeep = select, include-other-group="Keep\\Team, G2"\n' in out
        assert "# [V5+ cascade] AllGone = select // dead" in out
        assert "# [V5+ cascade] DOMAIN,dead.example,AllGone" in out
        assert "\nFINAL,DropGone\n" in out

    def test_parse_include_other_groups_direct_helpers(self):
        from converter import format_include_other_groups, parse_include_other_groups
        assert parse_include_other_groups('"G1,G2" # 说明') == ["G1", "G2"]
        assert parse_include_other_groups('"Gone\\\\Team,G2"') == ["Gone\\Team", "G2"]
        assert parse_include_other_groups('"A\\"B, G2"') == ['A"B', "G2"]
        assert format_include_other_groups(["Keep\\Team"], was_quoted=True) == "Keep\\Team"
        assert format_include_other_groups(["Keep\\Team", "G2"], was_quoted=True) == '"Keep\\Team, G2"'
        with pytest.raises(ValueError):
            format_include_other_groups(['A"B'], was_quoted=True)
        with pytest.raises(ValueError):
            format_include_other_groups(["HK, Fast"], was_quoted=True)


# --- T82: Round 2 fixes — root-scoped rulesets, section-scoped includes, paren passwords, rule trees, builtin precedence, WG fields, FINAL guard, rule whitespace, v4 encoding ---

class TestRound2Fixes:
    WG_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    WG_PUB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

    def test_two_profiles_same_dir_same_ruleset_name_do_not_overwrite(self, tmp_path):
        ios = tmp_path / "ios.conf"
        mac = tmp_path / "mac.conf"
        ios.write_text(textwrap.dedent("""\
            [Ruleset Shared]
            DOMAIN-SUFFIX,ios.example

            [Rule]
            RULE-SET,Shared,DIRECT
            FINAL,DIRECT
        """))
        mac.write_text(textwrap.dedent("""\
            [Ruleset Shared]
            DOMAIN-SUFFIX,mac.example

            [Rule]
            RULE-SET,Shared,DIRECT
            FINAL,DIRECT
        """))
        stats_ios = ConversionStats()
        stats_mac = ConversionStats()
        convert_file(str(ios), stats_ios)
        convert_file(str(mac), stats_mac)

        assert stats_mac.deprecated_files == []
        ios_v4 = (tmp_path / "v4" / "ios-v4.conf").read_text()
        mac_v4 = (tmp_path / "v4" / "mac-v4.conf").read_text()
        ios_lists = list((tmp_path / "v4").glob("ios-Shared-*-ruleset-v4.list"))
        mac_lists = list((tmp_path / "v4").glob("mac-Shared-*-ruleset-v4.list"))
        assert len(ios_lists) == 1 and len(mac_lists) == 1
        assert ios_lists[0] != mac_lists[0]
        assert f"RULE-SET,{ios_lists[0].name},DIRECT" in ios_v4
        assert f"RULE-SET,{mac_lists[0].name},DIRECT" in mac_v4
        assert ios_lists[0].read_text() == "DOMAIN-SUFFIX,ios.example\n"
        assert mac_lists[0].read_text() == "DOMAIN-SUFFIX,mac.example\n"

    def test_unloaded_subfile_group_does_not_kill_live_underlying_proxy(self, tmp_path):
        (tmp_path / "catalog.dconf").write_text(textwrap.dedent("""\
            [Proxy]
            Exit = snell, 2.2.2.2, 8000, psk=a, version=4, underlying-proxy=Entry
            V5Dead = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000

            [Proxy Group]
            Entry = select, V5Dead
        """))
        main = tmp_path / "main.conf"
        main.write_text(textwrap.dedent("""\
            [Proxy]
            OK = snell, 3.3.3.3, 8000, psk=b, version=4
            #!include catalog.dconf

            [Proxy Group]
            Entry = select, OK

            [Rule]
            FINAL,Exit
        """))
        out = convert_file(str(main))
        assert out is not None
        scoped_cats = list((tmp_path / "v4").glob("main-catalog-*-v4.dconf"))
        assert len(scoped_cats) == 1
        cat_v4 = scoped_cats[0].read_text()
        assert "\nExit = snell, 2.2.2.2, 8000, psk=a, version=4, underlying-proxy=Entry\n" in "\n" + cat_v4
        assert "# [V5+ cascade] Exit" not in cat_v4
        main_v4 = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert f"#!include {scoped_cats[0].name}" in main_v4
        assert "\nFINAL,Exit\n" in main_v4

    def test_unloaded_subfile_ruleset_does_not_dirty_clean_profile_or_abandon_managed(self, tmp_path):
        (tmp_path / "catalog.dconf").write_text(textwrap.dedent("""\
            [Proxy]
            OK = snell, 2.2.2.2, 8000, psk=a, version=4

            [Ruleset Dormant]
            DOMAIN-SUFFIX,dormant.example
        """))
        managed = tmp_path / "sub.conf"
        managed.write_text(textwrap.dedent("""\
            #!MANAGED-CONFIG https://example.com/sub.conf interval=86400
            [Proxy]
            M1 = snell, 3.3.3.3, 8000, psk=b, version=4
        """))
        main = tmp_path / "main.conf"
        main.write_text(textwrap.dedent("""\
            [Proxy]
            #!include catalog.dconf

            [Proxy Group]
            Sub = select, policy-path=sub.conf

            [Rule]
            FINAL,Sub
        """))
        stats = ConversionStats()
        result = convert_file(str(main), stats)
        assert result is None
        assert stats.abandoned_files == []
        assert not (tmp_path / "v4").exists()

    def test_unquoted_password_with_literal_paren_does_not_swallow_options(self, tmp_path):
        line = "Safe = trojan, 192.0.2.10, 443, password=left(, ecn=true, block-quic=on"
        cleaned, removed = remove_proxy_params(line, V5PLUS_ONLY_PROXY_PARAMS)
        assert cleaned == "Safe = trojan, 192.0.2.10, 443, password=left("
        assert set(removed) == {"ecn", "block-quic"}

        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            Entry = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            Exit = snell, 2.2.2.2, 8000, psk=left(, version=4, underlying-proxy=Entry
            Safe = trojan, 192.0.2.10, 443, password=left(, ecn=true, block-quic=on

            [Rule]
            DOMAIN,a.example,Exit
            FINAL,Safe
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] Exit = snell" in out
        assert "# [V5+ cascade] DOMAIN,a.example,Exit" in out
        assert "Safe = trojan, 192.0.2.10, 443, password=left(\n" in out

    def test_nested_ruleset_expanded_and_logical_ruleset_rewritten(self, tmp_path):
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Ruleset Inner]
            DOMAIN-SUFFIX,inner.example
            DOMAIN-WILDCARD ,*.skip.example

            [Ruleset Outer]
            RULE-SET,Inner
            IP-CIDR,10.0.0.0/24,no-resolve

            [Ruleset Office]
            DOMAIN-SUFFIX,office.example

            [Ruleset BadNested]
            RULE-SET,https://example.com/remote.list

            [Rule]
            RULE-SET,Outer,DIRECT
            AND,((PROTOCOL,TCP),(RULE-SET,Office)),REJECT
            AND,((PROTOCOL,TCP),(RULE-SET,BadNested)),REJECT
            FINAL,DIRECT
        """))
        stats = ConversionStats()
        convert_file(str(root), stats)
        out = (tmp_path / "v4" / "profile-v4.conf").read_text()
        outer_files = list((tmp_path / "v4").glob("profile-Outer-*-ruleset-v4.list"))
        office_files = list((tmp_path / "v4").glob("profile-Office-*-ruleset-v4.list"))
        assert len(outer_files) == 1 and len(office_files) == 1
        assert list((tmp_path / "v4").glob("*Inner*")) == []
        assert list((tmp_path / "v4").glob("*BadNested*")) == []

        outer_text = outer_files[0].read_text()
        assert "DOMAIN-SUFFIX,inner.example" in outer_text
        assert "# [V5+] DOMAIN-WILDCARD ,*.skip.example" in outer_text
        assert "IP-CIDR,10.0.0.0/24,no-resolve" in outer_text
        assert "RULE-SET,Inner" not in outer_text

        assert f"RULE-SET,{outer_files[0].name},DIRECT" in out
        assert f"AND,((PROTOCOL,TCP),(RULE-SET,{office_files[0].name})),REJECT" in out
        assert "# [V5+ cascade] AND,((PROTOCOL,TCP),(RULE-SET,BadNested)),REJECT" in out

    def test_builtin_lan_and_system_precedence_over_inline_ruleset(self, tmp_path):
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Ruleset LAN]
            DOMAIN-SUFFIX,fake-lan.example

            [Ruleset SYSTEM]
            DOMAIN-SUFFIX,fake-sys.example

            [Rule]
            RULE-SET,LAN,REJECT
            RULE-SET,SYSTEM,DIRECT
            AND,((PROTOCOL,TCP),(RULE-SET,LAN)),REJECT
            FINAL,DIRECT
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert "# [V5+] [Ruleset LAN]" in out
        assert "# [V5+] [Ruleset SYSTEM]" in out
        assert "\nRULE-SET,LAN,REJECT\n" in out
        assert "\nRULE-SET,SYSTEM,DIRECT\n" in out
        assert "\nAND,((PROTOCOL,TCP),(RULE-SET,LAN)),REJECT\n" in out
        assert list((tmp_path / "v4").glob("*.list")) == []

    def test_incomplete_wireguard_section_after_abandoned_or_remote_include_cascades(self, tmp_path):
        managed = tmp_path / "managed-wg.dconf"
        managed.write_text(textwrap.dedent(f"""\
            #!MANAGED-CONFIG https://example.com/wg.dconf interval=86400
            [WireGuard office]
            private-key = {self.WG_KEY}
            self-ip = 10.20.0.2
            peer = (public-key = {self.WG_PUB}, allowed-ips = "10.20.0.0/24", endpoint = 1.2.3.4:51820)
        """))
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            OfficeWG = wireguard, section-name=office
            RemoteWG = wireguard, section-name=remote

            [WireGuard office]
            mtu = 1280
            #!include managed-wg.dconf

            [WireGuard remote]
            mtu = 1280
            #!include https://example.com/remote-wg.conf

            [Rule]
            DOMAIN,corp.example,OfficeWG
            DOMAIN,rem.example,RemoteWG
            FINAL,DIRECT
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert "# [V5+ cascade] [WireGuard office]" in out
        assert "# [V5+ cascade] mtu = 1280" in out
        assert "# [V5+ cascade] OfficeWG = wireguard, section-name=office" in out
        assert "# [V5+ cascade] [WireGuard remote]" in out
        assert "# [V5+ cascade] RemoteWG = wireguard, section-name=remote" in out
        assert "# [V5+ cascade] DOMAIN,corp.example,OfficeWG" in out
        assert "# [V5+ cascade] DOMAIN,rem.example,RemoteWG" in out

    def test_missing_final_after_underlying_proxy_cascade_stops_emit_and_exits(self, tmp_path, monkeypatch):
        from converter import main as converter_main

        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            Entry = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            Exit = snell, 2.2.2.2, 8000, psk=a, version=4, underlying-proxy=Entry

            [Rule]
            FINAL,Exit
        """))
        stats = ConversionStats()
        result = convert_file(str(root), stats)
        assert result is None
        assert not (tmp_path / "v4" / "main-v4.conf").exists()
        assert any("FINAL" in e for e in stats.errors)

        monkeypatch.setattr("sys.argv", ["converter.py", str(root)])
        with pytest.raises(SystemExit) as exc:
            converter_main()
        assert exc.value.code == 1

    def test_rule_type_with_space_before_comma_downgraded(self):
        result = convert("""
            [Rule]
            DOMAIN-WILDCARD ,*.example.test,DIRECT
            HOSTNAME-TYPE , IPv4 , DIRECT
            FINAL,DIRECT
        """)
        assert "# [V5+] DOMAIN-WILDCARD ,*.example.test,DIRECT" in result
        assert "# [V5+] HOSTNAME-TYPE , IPv4 , DIRECT" in result

    def test_v4_unrepresentable_surviving_group_name_reports_error_and_stops(self, tmp_path):
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            V5 = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            OK = snell, 2.2.2.2, 8000, psk=a, version=4

            [Proxy Group]
            Gone = select, V5
            "A\\"B" = select, OK
            Merged = select, include-other-group="Gone,A\\"B"

            [Rule]
            FINAL,Merged
        """))
        stats = ConversionStats()
        result = convert_file(str(root), stats)
        assert result is None
        assert not (tmp_path / "v4" / "main-v4.conf").exists()
        assert any('A"B' in e for e in stats.errors)


# --- T83: Round 3 fixes — shared rule subfile isolation, policy-path visibility, deferred iog v4 finalize, WG remote strip, NOT negation safety ---

class TestRound3Fixes:
    WG_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    WG_PUB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

    def test_shared_rule_subfile_isolated_per_root_profile(self, tmp_path):
        (tmp_path / "rules.dconf").write_text("[Rule]\nRULE-SET,Shared,DIRECT\n")
        ios = tmp_path / "ios.conf"
        mac = tmp_path / "mac.conf"
        ios.write_text(textwrap.dedent("""\
            [Ruleset Shared]
            DOMAIN-SUFFIX,ios.example

            [Rule]
            #!include rules.dconf
            FINAL,DIRECT
        """))
        mac.write_text(textwrap.dedent("""\
            [Ruleset Shared]
            DOMAIN-SUFFIX,mac.example

            [Rule]
            #!include rules.dconf
            FINAL,DIRECT
        """))
        stats_ios = ConversionStats()
        stats_mac = ConversionStats()
        convert_file(str(ios), stats_ios)
        convert_file(str(mac), stats_mac)

        assert stats_mac.deprecated_files == []
        ios_v4 = (tmp_path / "v4" / "ios-v4.conf").read_text()
        mac_v4 = (tmp_path / "v4" / "mac-v4.conf").read_text()
        ios_rules = list((tmp_path / "v4").glob("ios-rules-*-v4.dconf"))
        mac_rules = list((tmp_path / "v4").glob("mac-rules-*-v4.dconf"))
        assert len(ios_rules) == 1 and len(mac_rules) == 1
        assert ios_rules[0] != mac_rules[0]
        assert f"#!include {ios_rules[0].name}" in ios_v4
        assert f"#!include {mac_rules[0].name}" in mac_v4
        ios_list = list((tmp_path / "v4").glob("ios-Shared-*-ruleset-v4.list"))[0]
        mac_list = list((tmp_path / "v4").glob("mac-Shared-*-ruleset-v4.list"))[0]
        assert f"RULE-SET,{ios_list.name},DIRECT" in ios_rules[0].read_text()
        assert f"RULE-SET,{mac_list.name},DIRECT" in mac_rules[0].read_text()

    def test_policy_path_node_does_not_shield_deleted_global_underlying_proxy(self, tmp_path):
        (tmp_path / "pool.conf").write_text(textwrap.dedent("""\
            [Proxy]
            Entry = snell, 1.1.1.1, 8000, psk=a, version=4
            Safe = snell, 2.2.2.2, 8000, psk=b, version=4
        """))
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            Entry = vless, 9.9.9.9, 443, username=00000000-0000-0000-0000-000000000000
            Exit = snell, 3.3.3.3, 8000, psk=c, version=4, underlying-proxy=Entry

            [Proxy Group]
            SafePool = select, policy-path=pool.conf, policy-regex-filter=^Safe$

            [Rule]
            DOMAIN,chain.example,Exit
            FINAL,SafePool
        """))
        convert_file(str(root))
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+] Entry = vless" in out
        assert "# [V5+ cascade] Exit = snell" in out
        assert "# [V5+ cascade] DOMAIN,chain.example,Exit" in out
        assert "\nFINAL,SafePool\n" in out

    def test_include_other_group_order_independent_and_preserves_double_backslash(self, tmp_path):
        # Consumer declared BEFORE the eventually-deleted quote-bearing group
        root1 = tmp_path / "before.conf"
        root1.write_text(textwrap.dedent("""\
            [Proxy]
            V5 = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            OK = snell, 2.2.2.2, 8000, psk=a, version=4

            [Proxy Group]
            Consumer = select, include-other-group="A\\"B, Safe"
            "A\\"B" = select, V5
            Safe = select, OK
            Keep\\\\Team = select, OK
            Gone = select, V5
            DoubleBS = select, include-other-group="Gone, Keep\\\\\\\\Team, Safe"

            [Rule]
            FINAL,Consumer
        """))
        stats1 = ConversionStats()
        out1 = convert_file(str(root1), stats1)
        assert out1 is not None
        assert stats1.errors == []
        text1 = (tmp_path / "v4" / "before-v4.conf").read_text()
        assert 'Consumer = select, include-other-group="Safe"\n' in text1
        # Two literal backslashes preserved (NOT collapsed to one across passes)
        assert 'DoubleBS = select, include-other-group="Keep\\\\Team, Safe"\n' in text1

        # Reversed order: "A\"B" declared BEFORE Consumer -> identical result
        root2 = tmp_path / "after.conf"
        root2.write_text(textwrap.dedent("""\
            [Proxy]
            V5 = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            OK = snell, 2.2.2.2, 8000, psk=a, version=4

            [Proxy Group]
            "A\\"B" = select, V5
            Safe = select, OK
            Consumer = select, include-other-group="A\\"B, Safe"

            [Rule]
            FINAL,Consumer
        """))
        stats2 = ConversionStats()
        out2 = convert_file(str(root2), stats2)
        assert out2 is not None
        assert stats2.errors == []
        assert 'Consumer = select, include-other-group="Safe"\n' in (tmp_path / "v4" / "after-v4.conf").read_text()

    def test_wireguard_strips_remote_include_even_when_local_fields_complete(self, tmp_path):
        (tmp_path / "local-wg.dconf").write_text(textwrap.dedent(f"""\
            [WireGuard office]
            private-key = {self.WG_KEY}
            self-ip = 10.20.0.2
            mtu = 1280
            peer = (public-key = {self.WG_PUB}, allowed-ips = "10.20.0.0/24", endpoint = 1.2.3.4:51820)
        """))
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Proxy]
            OfficeWG = wireguard, section-name=office

            [WireGuard office]
            #!include local-wg.dconf, https://example.com/remote-wg.conf

            [Rule]
            DOMAIN,corp.example,OfficeWG
            FINAL,DIRECT
        """))
        out = convert_file(str(root))
        assert out is not None
        text = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert "https://example.com/remote-wg.conf" not in text
        assert "#!include local-wg-v4.dconf" in text
        assert "\nOfficeWG = wireguard, section-name=office\n" in text
        assert "\nDOMAIN,corp.example,OfficeWG\n" in text

    def test_not_rule_referencing_narrowed_ruleset_is_cascaded(self, tmp_path):
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Ruleset Office]
            DOMAIN-WILDCARD,*.office.example.test
            DOMAIN,portal.office.example.test

            [Ruleset CleanOffice]
            DOMAIN,portal.office.example.test

            [Rule]
            NOT,((RULE-SET,Office)),REJECT
            AND,((PROTOCOL,TCP),(NOT,((RULE-SET,Office)))),REJECT
            NOT,((RULE-SET,CleanOffice)),REJECT
            FINAL,DIRECT
        """))
        stats = ConversionStats()
        convert_file(str(root), stats)
        out = (tmp_path / "v4" / "profile-v4.conf").read_text()
        assert "# [V5+ cascade] NOT,((RULE-SET,Office)),REJECT" in out
        assert "# [V5+ cascade] AND,((PROTOCOL,TCP),(NOT,((RULE-SET,Office)))),REJECT" in out
        # Narrowed Office had only negated refs -> no orphan .list emitted
        assert list((tmp_path / "v4").glob("profile-Office-*")) == []
        # Un-narrowed CleanOffice stays valid under NOT
        clean_lists = list((tmp_path / "v4").glob("profile-CleanOffice-*-ruleset-v4.list"))
        assert len(clean_lists) == 1
        assert f"NOT,((RULE-SET,{clean_lists[0].name})),REJECT" in out


class TestRound4Fixes:
    """Regression tests for Round 4 findings:
    1. Universal root-scoped isolation for any root-dependent sub-file
    2. Length-bounded scoped filenames + pre-emit NAME_MAX validation
    3. Strict one-way phase ordering: rewrite references before v4 iog writeback
    4. extended-matching narrowing under NOT and inside AND/OR/NOT sub-rules
    """

    def test_shared_subfile_cascaded_by_one_root_isolated_from_other_root(self, tmp_path):
        (tmp_path / "common.dconf").write_text(textwrap.dedent("""\
            [Proxy]
            Exit = snell, 2.2.2.2, 8000, psk=a, version=4, underlying-proxy=Entry
            OK = snell, 3.3.3.3, 8000, psk=b, version=4
        """))
        ios = tmp_path / "ios.conf"
        ios.write_text(textwrap.dedent("""\
            [Proxy]
            Entry = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            #!include common.dconf

            [Rule]
            FINAL,OK
        """))
        mac = tmp_path / "mac.conf"
        mac.write_text(textwrap.dedent("""\
            [Proxy]
            Entry = snell, 1.1.1.1, 8000, psk=c, version=4
            Dead = anytls, 4.4.4.4, 443, password=pwd
            #!include common.dconf

            [Rule]
            FINAL,Exit
        """))
        # Convert ios then mac — mac must NOT overwrite ios's cascaded common.dconf
        convert_file(str(ios))
        convert_file(str(mac))

        ios_v4 = (tmp_path / "v4" / "ios-v4.conf").read_text()
        mac_v4 = (tmp_path / "v4" / "mac-v4.conf").read_text()
        ios_common_files = list((tmp_path / "v4").glob("ios-common-*-v4.dconf"))
        assert len(ios_common_files) == 1
        assert f"#!include {ios_common_files[0].name}" in ios_v4
        assert "# [V5+ cascade] Exit = snell" in ios_common_files[0].read_text()
        assert "#!include common-v4.dconf" in mac_v4
        assert "\nExit = snell, 2.2.2.2" in (tmp_path / "v4" / "common-v4.dconf").read_text()

        # Reverse order: converting ios again must NOT overwrite mac's common-v4.dconf
        convert_file(str(ios))
        assert "\nExit = snell, 2.2.2.2" in (tmp_path / "v4" / "common-v4.dconf").read_text()
        assert "# [V5+ cascade] Exit = snell" in ios_common_files[0].read_text()

    def test_shared_ancestor_of_cascaded_subfile_is_also_isolated(self, tmp_path):
        (tmp_path / "leaf.dconf").write_text(
            "[Proxy]\nExit = snell, 2.2.2.2, 8000, psk=a, version=4, underlying-proxy=Entry\n"
            "OK = snell, 3.3.3.3, 8000, psk=b, version=4\n"
        )
        (tmp_path / "wrapper.dconf").write_text("[Proxy]\n#!include leaf.dconf\n")
        ios = tmp_path / "ios.conf"
        ios.write_text(textwrap.dedent("""\
            [Proxy]
            Entry = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            #!include wrapper.dconf

            [Rule]
            FINAL,OK
        """))
        mac = tmp_path / "mac.conf"
        mac.write_text(textwrap.dedent("""\
            [Proxy]
            Entry = snell, 1.1.1.1, 8000, psk=c, version=4
            Dead = anytls, 4.4.4.4, 443, password=pwd
            #!include wrapper.dconf

            [Rule]
            FINAL,Exit
        """))
        convert_file(str(ios))
        convert_file(str(mac))

        ios_wrappers = list((tmp_path / "v4").glob("ios-wrapper-*-v4.dconf"))
        ios_leaves = list((tmp_path / "v4").glob("ios-leaf-*-v4.dconf"))
        assert len(ios_wrappers) == 1 and len(ios_leaves) == 1
        assert f"#!include {ios_wrappers[0].name}" in (tmp_path / "v4" / "ios-v4.conf").read_text()
        assert f"#!include {ios_leaves[0].name}" in ios_wrappers[0].read_text()
        assert "#!include wrapper-v4.dconf" in (tmp_path / "v4" / "mac-v4.conf").read_text()
        assert "#!include leaf-v4.dconf" in (tmp_path / "v4" / "wrapper-v4.dconf").read_text()

    def test_long_root_and_subfile_names_stay_within_name_max(self, tmp_path):
        root_name = ("r" * 131) + ".conf"
        sub_name = ("s" * 133) + ".dconf"
        long_rs = "Ruleset" + ("x" * 120)
        (tmp_path / sub_name).write_text(f"[Rule]\nRULE-SET,{long_rs},DIRECT\n")
        root = tmp_path / root_name
        root.write_text(textwrap.dedent(f"""\
            [Ruleset {long_rs}]
            DOMAIN,corp.example.test

            [Rule]
            #!include {sub_name}
            FINAL,DIRECT
        """))
        stats = ConversionStats()
        out_path = convert_file(str(root), stats)
        assert out_path is not None
        assert stats.errors == []

        v4_files = list((tmp_path / "v4").iterdir())
        assert len(v4_files) == 3  # root, scoped subfile, scoped ruleset .list
        for f in v4_files:
            assert len(f.name.encode("utf-8")) <= 255
        scoped_files = [f for f in v4_files if f.name != Path(out_path).name]
        assert len(scoped_files) == 2
        for f in scoped_files:
            # Must leave headroom for -deprecated backup
            assert len((f.stem + "-deprecated" + f.suffix).encode("utf-8")) <= 255

        # Re-running with changed ruleset must back up to -deprecated without OSError
        root.write_text(textwrap.dedent(f"""\
            [Ruleset {long_rs}]
            DOMAIN,corp2.example.test

            [Rule]
            #!include {sub_name}
            FINAL,DIRECT
        """))
        stats2 = ConversionStats()
        assert convert_file(str(root), stats2) is not None
        assert stats2.errors == []
        assert len(stats2.deprecated_files) >= 1

    def test_pre_emit_path_length_validation_aborts_before_writing_anything(self, tmp_path, monkeypatch):
        sub = tmp_path / "common.dconf"
        sub.write_text("[Proxy]\nOK = snell, 1.1.1.1, 8000, psk=a, version=4\n")
        root = tmp_path / (("a" * 50) + ".conf")
        root.write_text(textwrap.dedent("""\
            [Proxy]
            Dead = anytls, 2.2.2.2, 443, password=pwd
            #!include common.dconf

            [Rule]
            FINAL,OK
        """))
        monkeypatch.setattr(converter, "_filename_too_long", lambda _d, name: len(name) > 40)
        stats = ConversionStats()
        res = convert_file(str(root), stats)
        assert res is None
        assert any("长度上限" in e for e in stats.errors)
        assert not (tmp_path / "v4").exists()

    def test_pre_emit_backup_length_validation_aborts_cleanly(self, tmp_path, monkeypatch):
        root = tmp_path / "profile-long-name.conf"  # profile-long-name-v4.conf = 25 chars, -deprecated = 36 chars
        root.write_text(textwrap.dedent("""\
            [Proxy]
            Dead = anytls, 2.2.2.2, 443, password=pwd
            OK = snell, 1.1.1.1, 8000, psk=a, version=4

            [Rule]
            FINAL,OK
        """))
        v4_dir = tmp_path / "v4"
        v4_dir.mkdir()
        existing = v4_dir / "profile-long-name-v4.conf"
        existing.write_text("old content\n")
        monkeypatch.setattr(converter, "_filename_too_long", lambda _d, name: len(name) > 30)
        stats = ConversionStats()
        res = convert_file(str(root), stats)
        assert res is None
        assert any("备份文件名超出文件系统长度上限" in e for e in stats.errors)
        # Existing v4 file must stay completely untouched
        assert existing.read_text() == "old content\n"

    def test_iog_trailing_backslash_and_policy_path_on_same_line(self, tmp_path):
        (tmp_path / "provider.dconf").write_text(
            "P1 = snell, 1.1.1.1, 8000, psk=a, version=4\n"
        )
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent(r"""
            [Proxy]
            Dead = anytls, 2.2.2.2, 443, password=pwd
            OK = snell, 3.3.3.3, 8000, psk=b, version=4

            [Proxy Group]
            Gone = select, Dead
            G1 = select, OK
            Keep\Team\ = select, OK
            Mix = select, include-other-group="Gone, G1, Keep\\Team\\", policy-path=provider.dconf

            [Rule]
            FINAL,Mix
        """).lstrip())
        stats = ConversionStats()
        out_path = convert_file(str(root), stats)
        assert out_path is not None
        assert stats.errors == []
        out = Path(out_path).read_text()
        assert (tmp_path / "v4" / "provider-v4.dconf").exists()
        assert r'Mix = select, include-other-group="G1, Keep\Team\", policy-path=provider-v4.dconf' in out

    def test_iog_escape_only_and_policy_path_on_same_line(self, tmp_path):
        (tmp_path / "provider.dconf").write_text(
            "P1 = snell, 1.1.1.1, 8000, psk=a, version=4\n"
        )
        root = tmp_path / "main.conf"
        root.write_text(textwrap.dedent(r"""
            [Proxy]
            OK = snell, 3.3.3.3, 8000, psk=b, version=4

            [Proxy Group]
            G1 = select, OK
            Keep\Team\ = select, OK
            Mix = select, include-other-group="G1, Keep\\Team\\", policy-path=provider.dconf

            [Rule]
            FINAL,Mix
        """).lstrip())
        stats = ConversionStats()
        out_path = convert_file(str(root), stats)
        assert out_path is not None
        assert stats.errors == []
        out = Path(out_path).read_text()
        assert (tmp_path / "v4" / "provider-v4.dconf").exists()
        assert r'Mix = select, include-other-group="G1, Keep\Team\", policy-path=provider-v4.dconf' in out

    def test_extended_matching_in_ruleset_narrows_not_and_logical_subrules(self, tmp_path):
        root = tmp_path / "profile.conf"
        root.write_text(textwrap.dedent("""\
            [Ruleset Office]
            DOMAIN,office.example.test,extended-matching

            [Ruleset CleanOffice]
            DOMAIN,portal.example.test

            [Ruleset LogicOffice]
            AND,((PROTOCOL,TCP),(DOMAIN,corp.example.test,extended-matching))

            [Rule]
            RULE-SET,Office,DIRECT
            NOT,((RULE-SET,Office)),REJECT
            AND,((PROTOCOL,TCP),(RULE-SET,Office,extended-matching)),REJECT
            NOT,((RULE-SET,CleanOffice,extended-matching)),REJECT
            NOT,((DOMAIN,a.example,extended-matching)),REJECT
            NOT,((NOT,((DOMAIN,b.example,extended-matching)))),REJECT
            NOT,((DOMAIN,c.example)),REJECT,extended-matching
            NOT,((RULE-SET,LogicOffice)),REJECT
            FINAL,DIRECT
        """))
        stats = ConversionStats()
        out_path = convert_file(str(root), stats)
        assert out_path is not None
        assert stats.errors == []
        out = Path(out_path).read_text()

        office_lists = list((tmp_path / "v4").glob("profile-Office-*-ruleset-v4.list"))
        assert len(office_lists) == 1
        office_list_text = office_lists[0].read_text()
        assert "DOMAIN,office.example.test" in office_list_text
        assert "extended-matching" not in office_list_text

        # Positive RULE-SET and positive logical sub-rule stay active with extended-matching stripped
        assert f"\nRULE-SET,{office_lists[0].name},DIRECT\n" in out
        assert f"\nAND,((PROTOCOL,TCP),(RULE-SET,{office_lists[0].name})),REJECT\n" in out
        # Narrowed Office under NOT must be cascade-commented
        assert "# [V5+ cascade] NOT,((RULE-SET,Office)),REJECT" in out
        # Negated sub-rules / outer NOT with extended-matching must be commented out
        assert "# [V5+] NOT,((RULE-SET,CleanOffice,extended-matching)),REJECT" in out
        assert "# [V5+] NOT,((DOMAIN,a.example,extended-matching)),REJECT" in out
        assert "# [V5+] NOT,((DOMAIN,c.example)),REJECT,extended-matching" in out
        # Double negation is positive polarity -> extended-matching stripped, rule stays
        assert "\nNOT,((NOT,((DOMAIN,b.example)))),REJECT\n" in out
        # Narrowed logical ruleset under NOT must be cascade-commented, no orphan .list
        assert "# [V5+ cascade] NOT,((RULE-SET,LogicOffice)),REJECT" in out
        assert list((tmp_path / "v4").glob("profile-LogicOffice-*")) == []
        assert list((tmp_path / "v4").glob("profile-CleanOffice-*")) == []


class TestRound5Fixes:
    """Regression tests for Round 5 findings:
    1. Two configs loading different sections of a shared subfile with local
       references (policy-path / #!include) never overwrite each other's rewrites
    2. Pre-emit filename validation respects real filesystem Unicode semantics
       (e.g. >255 UTF-8 byte Chinese filenames allowed by APFS) and backup renames
    3. Trailing extended-matching on nested compound (AND/OR/NOT) sub-rules and
       on outer logical rules containing nested NOT
    """

    def test_shared_subfile_different_loaded_sections_preserve_policy_path_rewrite(self, tmp_path):
        (tmp_path / "provider.dconf").write_text(
            "[Proxy]\nSub = snell, 2.2.2.2, 8000, psk=b, version=4\n"
        )
        (tmp_path / "catalog.dconf").write_text(textwrap.dedent("""\
            [Proxy]
            DirectProxy = snell, 1.1.1.1, 8000, psk=a, version=4

            [Proxy Group]
            G = select, policy-path=provider.dconf
        """))
        cfg_a = tmp_path / "a.conf"
        cfg_a.write_text(textwrap.dedent("""\
            [Proxy]
            DeadA = anytls, 9.9.9.9, 443, password=pwd

            [Proxy Group]
            #!include catalog.dconf

            [Rule]
            FINAL,G
        """))
        cfg_b = tmp_path / "b.conf"
        cfg_b.write_text(textwrap.dedent("""\
            [Proxy]
            DeadB = anytls, 8.8.8.8, 443, password=pwd
            #!include catalog.dconf

            [Rule]
            FINAL,DirectProxy
        """))

        # Order A -> B: B must NOT overwrite A's rewritten catalog-v4.dconf
        convert_file(str(cfg_a))
        convert_file(str(cfg_b))

        a_out = (tmp_path / "v4" / "a-v4.conf").read_text()
        b_out = (tmp_path / "v4" / "b-v4.conf").read_text()
        assert "#!include catalog-v4.dconf" in a_out
        assert "policy-path=provider-v4.dconf" in (tmp_path / "v4" / "catalog-v4.dconf").read_text()
        assert (tmp_path / "v4" / "provider-v4.dconf").exists()

        b_catalogs = list((tmp_path / "v4").glob("b-catalog-*-v4.dconf"))
        assert len(b_catalogs) == 1
        assert f"#!include {b_catalogs[0].name}" in b_out
        assert "DirectProxy = snell" in b_catalogs[0].read_text()

        # Reverse order B -> A must stay identical and intact
        convert_file(str(cfg_a))
        assert "policy-path=provider-v4.dconf" in (tmp_path / "v4" / "catalog-v4.dconf").read_text()
        assert f"#!include {b_catalogs[0].name}" in (tmp_path / "v4" / "b-v4.conf").read_text()

    def test_shared_subfile_both_roots_have_unloaded_refs_in_opposite_sections(self, tmp_path):
        (tmp_path / "p1.dconf").write_text("[Proxy]\nP1 = snell, 1.1.1.1, 8000, psk=a, version=4\n")
        (tmp_path / "p2.dconf").write_text("[Proxy]\nP2 = snell, 2.2.2.2, 8000, psk=b, version=4\n")
        (tmp_path / "catalog.dconf").write_text(textwrap.dedent("""\
            [Proxy]
            #!include p1.dconf

            [Proxy Group]
            G = select, policy-path=p2.dconf
        """))
        cfg_a = tmp_path / "a.conf"
        cfg_a.write_text("[Proxy]\nDeadA = anytls, 9.9.9.9, 443, password=pwd\n[Proxy Group]\n#!include catalog.dconf\n[Rule]\nFINAL,G\n")
        cfg_b = tmp_path / "b.conf"
        cfg_b.write_text("[Proxy]\nDeadB = anytls, 8.8.8.8, 443, password=pwd\n#!include catalog.dconf\n[Rule]\nFINAL,P1\n")

        convert_file(str(cfg_a))
        convert_file(str(cfg_b))

        a_cats = list((tmp_path / "v4").glob("a-catalog-*-v4.dconf"))
        b_cats = list((tmp_path / "v4").glob("b-catalog-*-v4.dconf"))
        assert len(a_cats) == 1 and len(b_cats) == 1
        assert "policy-path=p2-v4.dconf" in a_cats[0].read_text()
        assert "#!include p1-v4.dconf" in b_cats[0].read_text()

    def test_multibyte_unicode_filename_allowed_by_filesystem_converts_and_backs_up(self, tmp_path):
        # 97 Chinese chars + ".conf" = 102 chars, 296 UTF-8 bytes (>255 bytes)
        cjk_name = ("配" * 97) + ".conf"
        root = tmp_path / cjk_name
        try:
            root.write_text(textwrap.dedent("""\
                [Proxy]
                Dead = anytls, 1.1.1.1, 443, password=pwd
                OK = snell, 2.2.2.2, 8000, psk=a, version=4

                [Rule]
                FINAL,OK
            """))
        except OSError:
            pytest.skip("Filesystem does not support >255 UTF-8 byte filenames")

        stats1 = ConversionStats()
        out1 = convert_file(str(root), stats1)
        assert out1 is not None
        assert stats1.errors == []
        assert Path(out1).exists()
        assert "# [V5+] Dead = anytls" in Path(out1).read_text()

        # Second run with changed content must back up cleanly to -deprecated
        root.write_text(textwrap.dedent("""\
            [Proxy]
            Dead = anytls, 1.1.1.1, 443, password=pwd
            OK = snell, 3.3.3.3, 8000, psk=a, version=4

            [Rule]
            FINAL,OK
        """))
        stats2 = ConversionStats()
        out2 = convert_file(str(root), stats2)
        assert out2 is not None
        assert stats2.errors == []
        assert len(stats2.deprecated_files) == 1
        assert Path(stats2.deprecated_files[0]).exists()

    def test_real_enametoolong_aborts_before_writing_anything(self, tmp_path):
        # 253 ASCII chars + ".conf" -> source is 258? Use 249 + ".conf" = 254B (legal source),
        # so "-v4.conf" = 257B (>255 on both APFS and ext4).
        src_name = ("a" * 249) + ".conf"
        root = tmp_path / src_name
        try:
            root.write_text(textwrap.dedent("""\
                [Proxy]
                Dead = anytls, 1.1.1.1, 443, password=pwd
                OK = snell, 2.2.2.2, 8000, psk=a, version=4

                [Rule]
                FINAL,OK
            """))
        except OSError:
            pytest.skip("Filesystem rejected 254-char source file")
        stats = ConversionStats()
        res = convert_file(str(root), stats)
        assert res is None
        assert any("长度上限" in e for e in stats.errors)
        assert not (tmp_path / "v4").exists()

    def test_nested_compound_subrule_extended_matching_and_polarity(self, tmp_path):
        # Standalone file containing ONLY a negated nested compound rule with extended-matching
        # must be detected as needing conversion and commented out.
        solo = tmp_path / "solo.conf"
        solo.write_text(textwrap.dedent("""\
            [Rule]
            NOT,((AND,((DOMAIN,office.example.test),(DOMAIN-SUFFIX,example.test)),extended-matching)),REJECT
            FINAL,DIRECT
        """))
        solo_out = convert_file(str(solo))
        assert solo_out is not None
        assert (
            "# [V5+] NOT,((AND,((DOMAIN,office.example.test),(DOMAIN-SUFFIX,example.test)),extended-matching)),REJECT"
            in Path(solo_out).read_text()
        )

        # Full polarity matrix across nested AND/OR/NOT and [Ruleset ...]
        root = tmp_path / "matrix.conf"
        root.write_text(textwrap.dedent("""\
            [Ruleset CompoundNarrowed]
            AND,((OR,((DOMAIN,x.test),(DOMAIN,y.test)),extended-matching),(PROTOCOL,TCP))

            [Rule]
            AND,((OR,((DOMAIN,a.test),(DOMAIN,b.test)),extended-matching),(PROTOCOL,TCP)),REJECT
            AND,((OR,((DOMAIN,a.test,extended-matching),(DOMAIN,b.test)),extended-matching),(PROTOCOL,TCP)),REJECT
            NOT,((AND,((DOMAIN,c.test),(DOMAIN-SUFFIX,d.test)),extended-matching)),REJECT
            AND,((NOT,((DOMAIN,e.test)),extended-matching),(PROTOCOL,TCP)),REJECT
            AND,((OR,((DOMAIN,f.test),(NOT,((DOMAIN,g.test)))),extended-matching),(PROTOCOL,TCP)),REJECT
            NOT,((NOT,((DOMAIN,h.test)),extended-matching)),REJECT
            AND,((PROTOCOL,TCP),(NOT,((DOMAIN,i.test)))),REJECT,extended-matching
            RULE-SET,CompoundNarrowed,DIRECT
            NOT,((RULE-SET,CompoundNarrowed)),REJECT
            FINAL,DIRECT
        """))
        out_path = convert_file(str(root))
        assert out_path is not None
        out = Path(out_path).read_text()
        # Positive nested compound -> extended-matching stripped cleanly
        # Both inner leaf and compound extended-matching stripped cleanly
        assert out.splitlines().count("AND,((OR,((DOMAIN,a.test),(DOMAIN,b.test))),(PROTOCOL,TCP)),REJECT") == 2
        # Negated compound sub-rules / compound containing NOT -> commented out
        assert "# [V5+] NOT,((AND,((DOMAIN,c.test),(DOMAIN-SUFFIX,d.test)),extended-matching)),REJECT" in out
        assert "# [V5+] AND,((NOT,((DOMAIN,e.test)),extended-matching),(PROTOCOL,TCP)),REJECT" in out
        assert "# [V5+] AND,((OR,((DOMAIN,f.test),(NOT,((DOMAIN,g.test)))),extended-matching),(PROTOCOL,TCP)),REJECT" in out
        assert "# [V5+] AND,((PROTOCOL,TCP),(NOT,((DOMAIN,i.test)))),REJECT,extended-matching" in out
        # Double negation -> positive polarity -> stripped safely
        assert "\nNOT,((NOT,((DOMAIN,h.test)))),REJECT\n" in out
        # Ruleset with nested compound extended-matching: stripped in .list, narrowed under NOT
        rs_files = list((tmp_path / "v4").glob("matrix-CompoundNarrowed-*-ruleset-v4.list"))
        assert len(rs_files) == 1
        rs_text = rs_files[0].read_text()
        assert "AND,((OR,((DOMAIN,x.test),(DOMAIN,y.test))),(PROTOCOL,TCP))" in rs_text
        assert "extended-matching" not in rs_text
        assert f"\nRULE-SET,{rs_files[0].name},DIRECT\n" in out
        assert "# [V5+ cascade] NOT,((RULE-SET,CompoundNarrowed)),REJECT" in out


class TestRound6Fixes:
    """Regression tests for Round 6 finding:
    A standalone-valid profile imported as a sub-file by another root must not
    collide with its own bare v4/<name>-v4.<ext> output when converted as root
    (in either conversion order).
    """

    def test_imported_profile_then_converted_standalone_and_reverse_order(self, tmp_path):
        shared_content = textwrap.dedent("""\
            [Proxy]
            Entry = vless, 1.1.1.1, 443, username=00000000-0000-0000-0000-000000000000
            Exit = snell, 2.2.2.2, 8000, psk=a, version=4, underlying-proxy=Entry
            OK = snell, 3.3.3.3, 8000, psk=b, version=4

            [Rule]
            FINAL,OK
        """)
        root_a_content = textwrap.dedent("""\
            [Proxy]
            Entry = snell, 9.9.9.9, 8000, psk=z, version=4
            Outer = snell, 8.8.8.8, 8000, psk=y, version=4, underlying-proxy=Exit
            #!include shared.conf

            [Rule]
            FINAL,Outer
        """)

        # Order 1: convert root-a first, then shared standalone
        d1 = tmp_path / "order1"
        d1.mkdir()
        shared1 = d1 / "shared.conf"
        root_a1 = d1 / "root-a.conf"
        shared1.write_text(shared_content)
        root_a1.write_text(root_a_content)

        convert_file(str(root_a1))
        convert_file(str(shared1))

        a1_out = (d1 / "v4" / "root-a-v4.conf").read_text()
        shared1_standalone = (d1 / "v4" / "shared-v4.conf").read_text()
        scoped_shared1 = list((d1 / "v4").glob("root-a-shared-*-v4.conf"))
        assert len(scoped_shared1) == 1
        assert f"#!include {scoped_shared1[0].name}" in a1_out
        assert "\nExit = snell, 2.2.2.2" in scoped_shared1[0].read_text()
        assert "# [V5+ cascade] Exit = snell" in shared1_standalone

        # Order 2: convert shared standalone first, then root-a
        d2 = tmp_path / "order2"
        d2.mkdir()
        shared2 = d2 / "shared.conf"
        root_a2 = d2 / "root-a.conf"
        shared2.write_text(shared_content)
        root_a2.write_text(root_a_content)

        convert_file(str(shared2))
        convert_file(str(root_a2))

        a2_out = (d2 / "v4" / "root-a-v4.conf").read_text()
        shared2_standalone = (d2 / "v4" / "shared-v4.conf").read_text()
        scoped_shared2 = list((d2 / "v4").glob("root-a-shared-*-v4.conf"))
        assert len(scoped_shared2) == 1
        assert f"#!include {scoped_shared2[0].name}" in a2_out
        assert "\nExit = snell, 2.2.2.2" in scoped_shared2[0].read_text()
        assert "# [V5+ cascade] Exit = snell" in shared2_standalone

    def test_imported_profile_with_unloaded_ruleset_section_isolated_from_standalone(self, tmp_path):
        shared = tmp_path / "shared.conf"
        shared.write_text(textwrap.dedent("""\
            [Proxy]
            OK = snell, 1.1.1.1, 8000, psk=a, version=4

            [Ruleset Office]
            DOMAIN,office.example.test

            [Rule]
            RULE-SET,Office,OK
            FINAL,DIRECT
        """))
        root_a = tmp_path / "root-a.conf"
        root_a.write_text(textwrap.dedent("""\
            [Proxy]
            Dead = anytls, 2.2.2.2, 443, password=pwd
            #!include shared.conf

            [Rule]
            FINAL,OK
        """))
        convert_file(str(root_a))
        convert_file(str(shared))

        a_out = (tmp_path / "v4" / "root-a-v4.conf").read_text()
        scoped = list((tmp_path / "v4").glob("root-a-shared-*-v4.conf"))
        assert len(scoped) == 1
        assert f"#!include {scoped[0].name}" in a_out
        assert "RULE-SET,shared-Office-" in (tmp_path / "v4" / "shared-v4.conf").read_text()
        assert "RULE-SET,Office,OK" in scoped[0].read_text()


class TestRound7Fixes:
    """Regression tests for Round 7 finding:
    Two CLI invocations with different --snell-legacy settings (enabled vs empty,
    empty vs enabled, or two distinct override files) must never overwrite an
    earlier root's referenced sub-file copy.
    """

    def _run_cli(self, monkeypatch, *argv):
        from converter import main as converter_main
        monkeypatch.setattr("sys.argv", ["converter.py", *argv])
        converter_main()

    def test_different_snell_legacy_between_importing_root_and_standalone_both_orders(
        self, tmp_path, monkeypatch
    ):
        shared_text = textwrap.dedent("""\
            [Proxy]
            Entry = snell, 1.1.1.1, 6000, psk=FAKE-V6, version=6
            OK = snell, 3.3.3.3, 8000, psk=FAKE-OK, version=4

            [Rule]
            FINAL,OK
        """)
        root_a_text = textwrap.dedent("""\
            [Proxy]
            Outer = snell, 8.8.8.8, 8000, psk=FAKE-OUTER, version=4, underlying-proxy=Entry
            #!include shared.conf

            [Rule]
            FINAL,Outer
        """)
        legacy_a_text = "[shared.conf]\nport = 7000\npsk = FAKE-LEGACY-A\n"
        legacy_b_text = "[shared.conf]\nport = 7001\npsk = FAKE-LEGACY-B\n"

        # Case 1: root-a with --snell-legacy, then shared standalone WITHOUT --snell-legacy
        d1 = tmp_path / "enabled_then_empty"
        d1.mkdir()
        (d1 / "shared.conf").write_text(shared_text)
        (d1 / "root-a.conf").write_text(root_a_text)
        ini_a1 = d1 / "enabled.ini"
        ini_a1.write_text(legacy_a_text)
        ini_a1.chmod(0o600)

        self._run_cli(monkeypatch, "--snell-legacy", str(ini_a1), str(d1 / "root-a.conf"))
        self._run_cli(monkeypatch, str(d1 / "shared.conf"))

        scoped1 = list((d1 / "v4").glob("root-a-shared-*-v4.conf"))
        assert len(scoped1) == 1
        assert f"#!include {scoped1[0].name}" in (d1 / "v4" / "root-a-v4.conf").read_text()
        assert "Entry = snell, 1.1.1.1, 7000, psk=FAKE-LEGACY-A, version=4" in scoped1[0].read_text()
        assert "# [V5+] Entry = snell, 1.1.1.1, 6000" in (d1 / "v4" / "shared-v4.conf").read_text()

        # Case 2: root-a WITHOUT --snell-legacy, then shared standalone WITH --snell-legacy
        d2 = tmp_path / "empty_then_enabled"
        d2.mkdir()
        (d2 / "shared.conf").write_text(shared_text)
        (d2 / "root-a.conf").write_text(
            "[Proxy]\nDead = anytls, 2.2.2.2, 443, password=pwd\n#!include shared.conf\n[Rule]\nFINAL,OK\n"
        )
        ini_a2 = d2 / "enabled.ini"
        ini_a2.write_text(legacy_a_text)
        ini_a2.chmod(0o600)

        self._run_cli(monkeypatch, str(d2 / "root-a.conf"))
        self._run_cli(monkeypatch, "--snell-legacy", str(ini_a2), str(d2 / "shared.conf"))

        scoped2 = list((d2 / "v4").glob("root-a-shared-*-v4.conf"))
        assert len(scoped2) == 1
        assert f"#!include {scoped2[0].name}" in (d2 / "v4" / "root-a-v4.conf").read_text()
        assert "# [V5+] Entry = snell, 1.1.1.1, 6000" in scoped2[0].read_text()
        assert "Entry = snell, 1.1.1.1, 7000, psk=FAKE-LEGACY-A, version=4" in (d2 / "v4" / "shared-v4.conf").read_text()

        # Case 3: root-a with legacy A, then shared standalone with legacy B
        d3 = tmp_path / "legacy_a_then_b"
        d3.mkdir()
        (d3 / "shared.conf").write_text(shared_text)
        (d3 / "root-a.conf").write_text(root_a_text)
        ini_a3 = d3 / "a.ini"
        ini_b3 = d3 / "b.ini"
        ini_a3.write_text(legacy_a_text)
        ini_b3.write_text(legacy_b_text)
        ini_a3.chmod(0o600)
        ini_b3.chmod(0o600)

        self._run_cli(monkeypatch, "--snell-legacy", str(ini_a3), str(d3 / "root-a.conf"))
        self._run_cli(monkeypatch, "--snell-legacy", str(ini_b3), str(d3 / "shared.conf"))

        scoped3 = list((d3 / "v4").glob("root-a-shared-*-v4.conf"))
        assert len(scoped3) == 1
        assert "7000, psk=FAKE-LEGACY-A" in scoped3[0].read_text()
        assert "7001, psk=FAKE-LEGACY-B" in (d3 / "v4" / "shared-v4.conf").read_text()








