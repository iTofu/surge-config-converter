"""Tests for Surge v5+ → v4 configuration converter."""

import os
import textwrap
from unittest.mock import patch

import pytest

from converter import (
    ConversionStats,
    _split_top_level_commas,
    backup_if_exists,
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
    transform_proxy_line,
    transform_rule_line,
    transform_general_line,
    unquote,
)


# --- Helpers ---

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
        # proxies.conf needs conversion, extra.dconf does not
        assert "#!include proxies-v4.conf, extra.dconf" in content

        # Check proxies-v4.conf (has v5+ content)
        proxies_v4 = tmp_path / "v4" / "proxies-v4.conf"
        assert proxies_v4.exists()
        p_content = proxies_v4.read_text()
        assert "# [V5+] HY2-US = hysteria2" in p_content
        assert "version=4" in p_content
        assert "version=5" not in p_content
        assert "TROJAN-HK = trojan" in p_content

        # extra.dconf is pure v4, no -v4 copy created
        assert not (tmp_path / "v4" / "extra-v4.dconf").exists()

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
        local = tmp_path / "home.dconf"
        local.write_text("S1 = snell, 1.2.3.4, 8000, psk=x, version=4\n")

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Proxy = select, policy-path=home.dconf\n"
            "Auto = smart, policy-path=https://sub.example.com/surge.conf, interval=300\n"
        )

        stats = ConversionStats()
        processed = {str(main): None}
        convert_file(str(main), stats, processed)

        content = (tmp_path / "v4" / "main-v4.conf").read_text()
        # home.dconf is pure v4, keeps original reference
        assert "policy-path=home.dconf" in content
        assert "policy-path=https://sub.example.com/surge.conf" in content

    def test_multiple_policy_path_refs_to_same_file_all_rewritten(self, tmp_path):
        """Regression: the same sub-file referenced by BOTH an #!include and
        multiple policy-path options must have ALL references rewritten to -v4,
        not just the first encounter."""
        sub = tmp_path / "mai.dconf"
        sub.write_text(
            "[Proxy]\nSNELL = snell, 1.2.3.4, 8000, psk=pwd, version=5\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include mai.dconf\n"
            "\n"
            "[Proxy Group]\n"
            "G1 = select, policy-path=mai.dconf\n"
            "G2 = select, policy-path=mai.dconf\n"
            "G3 = select, policy-path=mai.dconf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include mai-v4.dconf" in out
        # All three references must be rewritten, not just the first
        assert out.count("policy-path=mai-v4.dconf") == 3
        assert "policy-path=mai.dconf" not in out


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
        """Only sub-files with changes get -v4 copies."""
        pure_v4 = tmp_path / "pure.conf"
        pure_v4.write_text("T1 = trojan, 1.2.3.4, 443, password=pwd\n")

        needs_conv = tmp_path / "needs-conv.conf"
        needs_conv.write_text("HY2 = hysteria2, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include pure.conf, needs-conv.conf\n")

        stats = ConversionStats()
        processed = {str(main): None}
        convert_file(str(main), stats, processed)

        assert not (tmp_path / "v4" / "pure-v4.conf").exists()
        assert (tmp_path / "v4" / "needs-conv-v4.conf").exists()
        content = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "#!include pure.conf, needs-conv-v4.conf" in content

    def test_policy_path_subfile_skipped(self, tmp_path):
        """policy-path sub-file with no changes → keep original reference."""
        local = tmp_path / "home.dconf"
        local.write_text("S1 = snell, 1.2.3.4, 8000, psk=x, version=4\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy Group]\nProxy = select, policy-path=home.dconf\n")

        stats = ConversionStats()
        processed = {str(main): None}
        result = convert_file(str(main), stats, processed)

        assert result is None
        assert not (tmp_path / "v4" / "home-v4.dconf").exists()

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
        assert make_v4_filename("/path/to/home.conf") == "/path/to/v4/home-v4.conf"

    def test_dconf(self):
        assert make_v4_filename("/path/to/self-vps.dconf") == "/path/to/v4/self-vps-v4.dconf"

    def test_relative(self):
        assert make_v4_filename("proxies.conf") == "v4/proxies-v4.conf"


class TestMakeV4Relname:
    def test_bare_filename(self):
        from converter import make_v4_relname
        assert make_v4_relname("mai-vps.dconf") == "mai-vps-v4.dconf"

    def test_strips_directory(self):
        from converter import make_v4_relname
        assert make_v4_relname("subdir/file.conf") == "file-v4.conf"

    def test_absolute_path(self):
        from converter import make_v4_relname
        assert make_v4_relname("/abs/path/home.conf") == "home-v4.conf"


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
        from converter import main as converter_main

        monkeypatch.setattr("sys.argv", ["converter.py", str(main_conf)])
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
        pgl = parse_proxy_group_line('✈️ Proxy = select, "💼 MAI", "♻️ Auto", DIRECT')
        assert pgl.name == "✈️ Proxy"
        assert pgl.members == ['"💼 MAI"', '"♻️ Auto"', "DIRECT"]

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
            'Proxy = select, "💼 MAI", "♻️ Auto", policy-path=xflash.conf'
        )
        assert pgl.members == ['"💼 MAI"', '"♻️ Auto"']
        assert pgl.options == [("policy-path", "xflash.conf")]

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
        line = '✈️ Proxy = select, "💼 MAI", "♻️ Auto", DIRECT'
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
            'Proxy = select, "💼 MAI", "🧑‍💻 SelfVPS", policy-path=sub.conf\n'
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert 'Proxy = select, "💼 MAI", "🧑‍💻 SelfVPS"' in out
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
        assert "#!include other.conf" in out
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
    def test_home_conf_with_abandoned_xflash(self, tmp_path):
        """Faithful reproduction of the user's home.conf + xflash structure."""
        xflash = tmp_path / "xflash-leodxkr.conf"
        xflash.write_text(
            "#!MANAGED-CONFIG https://www.xflash.org/api/v1/abc interval=43200 strict=true\n"
            "[Proxy]\n"
            "🇯🇵 日本 = anytls, 03.giant.jp.matchacocoa.com, 35000, password=pwd\n"
            "🇭🇰 香港 = trojan, 03.giant.hk.matchacocoa.com, 443, password=pwd\n"
            "🇺🇸 美国 = anytls, 03.giant.us.matchacocoa.com, 35000, password=pwd\n"
        )
        (tmp_path / "mai-vps.dconf").write_text(
            "[Proxy]\n🇺🇸 MA-DMIT-US-SNELL = snell, 01.study.us, 7443, psk=pwd, version=5\n"
        )
        (tmp_path / "self-vps.dconf").write_text(
            "[Proxy]\n# commented out\n"
        )
        (tmp_path / "self-home.dconf").write_text(
            "[Proxy]\n🏡 HomeSnell = snell, home.x, 6161, psk=pwd, version=5\n"
        )

        home = tmp_path / "home.conf"
        home.write_text(
            "[General]\n"
            "loglevel = notify\n"
            "proxy-test-url = http://cp.cloudflare.com/generate_204\n"
            "\n"
            "[Proxy]\n"
            "#!include xflash-leodxkr.conf, mai-vps.dconf, self-vps.dconf, self-home.dconf\n"
            "\n"
            "[Proxy Group]\n"
            '✈️ Proxy = select, "💼 MAI", "♻️ Auto", "🧑‍💻 SelfVPS", "🏡 HomeProxy", policy-path=xflash-leodxkr.conf\n'
            "♻️ Auto = smart, policy-path=xflash-leodxkr.conf, interval=300\n"
            '💼 MAI = select, include-all-proxies=1\n'
            '🧑‍💻 SelfVPS = select, include-all-proxies=1\n'
            '🏡 HomeProxy = select, include-all-proxies=1\n'
            "\n"
            "[Rule]\n"
            'DOMAIN-SUFFIX,example.com,"✈️ Proxy"\n'
            "FINAL,✈️ Proxy\n"
        )

        stats = ConversionStats()
        convert_file(str(home), stats, {str(home): None})

        # 1. xflash-leodxkr.conf abandoned — no -v4 file written
        assert not (tmp_path / "v4" / "xflash-leodxkr-v4.conf").exists()
        assert str(xflash) in stats.abandoned_files

        # 2. home-v4.conf produced
        home_v4 = tmp_path / "v4" / "home-v4.conf"
        assert home_v4.exists()
        out = home_v4.read_text()

        # 3. Include line: xflash removed, mai/self-home rewritten to -v4,
        #    self-vps kept (pure v4, no conversion)
        assert "xflash-leodxkr.conf" not in out
        assert "xflash-leodxkr-v4.conf" not in out
        assert "mai-vps-v4.dconf" in out
        assert "self-home-v4.dconf" in out
        assert "self-vps.dconf" in out

        # 4. ✈️ Proxy lost policy-path, lost ♻️ Auto (cascaded), kept other 3
        assert '✈️ Proxy = select, "💼 MAI", "🧑‍💻 SelfVPS", "🏡 HomeProxy"' in out

        # 5. ♻️ Auto cascaded to empty → commented
        assert "# [V5+ cascade] ♻️ Auto = url-test, interval=300" in out

        # 6. Other Proxy Groups untouched
        assert '💼 MAI = select, include-all-proxies=1' in out

        # 7. Rules unchanged (✈️ Proxy still exists)
        assert 'DOMAIN-SUFFIX,example.com,"✈️ Proxy"' in out
        assert "FINAL,✈️ Proxy" in out

        # 8. Sub-file mai-vps-v4.dconf has Snell version downgraded
        assert (tmp_path / "v4" / "mai-vps-v4.dconf").exists()
        mai_out = (tmp_path / "v4" / "mai-vps-v4.dconf").read_text()
        assert "version=4" in mai_out
        assert "version=5" not in mai_out

    def test_stale_xflash_v4_detected_not_deleted(self, tmp_path):
        """If xflash-v4 exists from a previous run, it's recorded in
        stats.stale_v4_files but NOT auto-deleted."""
        xflash = tmp_path / "xflash.conf"
        xflash.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        (tmp_path / "v4").mkdir()
        stale = tmp_path / "v4" / "xflash-v4.conf"
        stale.write_text("stale content")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include xflash.conf\n")

        stats = ConversionStats()
        with patch("converter.send2trash") as mock_trash:
            convert_file(str(main), stats, {str(main): None})
            # send2trash called only for deprecated_files path, NOT for stale v4
            assert mock_trash.call_count == 0

        assert stale.exists()
        assert stale.read_text() == "stale content"
        assert str(stale) in stats.stale_v4_files
        assert str(xflash) in stats.abandoned_files


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
        # Expect at least: JP commented (direct), OnlyV5 cascade, rule cascade
        assert stats.lines_commented >= 3

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
    def test_final_rule_policy_cascade_deleted(self, tmp_path):
        """FINAL,GroupName where GroupName gets cascade-deleted."""
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
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] OnlyV5 = select" in out
        assert "# [V5+ cascade] FINAL,OnlyV5" in out

    def test_final_rule_with_dns_failed_cascade(self, tmp_path):
        """FINAL,GroupName,dns-failed — trailing option must not confuse policy extraction."""
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
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+ cascade] FINAL,OnlyV5,dns-failed" in out


# --- T37: Snell version regex boundary ---

class TestSnellVersionBoundary:
    def test_version_50_not_downgraded(self):
        """version=50 must NOT be matched by the \\b boundary."""
        result = convert("""
            [Proxy]
            S1 = snell, x.com, 443, psk=pwd, version=50
        """)
        assert "version=50" in result
        assert "version=4" not in result

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
        assert "#!include other.conf" in out
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
            "#!include groups.dconf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        main_out = (tmp_path / "v4" / "main-v4.conf").read_text()
        assert "# [V5+] JP = anytls" in main_out
        # The group is in groups-v4.dconf — JP must be removed from it
        sub_out = (tmp_path / "v4" / "groups-v4.dconf").read_text()
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
            "#!include groups.dconf\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        sub_out = (tmp_path / "v4" / "groups-v4.dconf").read_text()
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
