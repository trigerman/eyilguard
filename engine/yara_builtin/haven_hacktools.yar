/*
 * Haven Shield - bundled YARA rules for common offensive-security tools.
 *
 * These are Haven's own rules (so they ship license-clean with the product, unlike
 * TLP-restricted community packs). They flag well-known hacktools by their
 * distinctive strings. Each requires 2+ markers to keep false positives low.
 * Add community / Malpedia rules into data/yara/ to extend coverage.
 */

rule HackTool_WinPEAS
{
    meta:
        description = "winPEAS - Windows privilege-escalation enumeration (PEASS-ng)"
        author = "Haven Shield"
        reference = "https://github.com/carlospolop/PEASS-ng"
    strings:
        $a1 = "winPEAS" ascii wide nocase
        $a2 = "PEASS-ng" ascii wide nocase
        $a3 = "carlospolop" ascii wide nocase
        $a4 = "peass" ascii wide nocase
    condition:
        2 of them
}

rule HackTool_Mimikatz
{
    meta:
        description = "mimikatz - credential dumping"
        author = "Haven Shield"
    strings:
        $a1 = "mimikatz" ascii wide nocase
        $a2 = "gentilkiwi" ascii wide nocase
        $a3 = "sekurlsa" ascii wide nocase
        $a4 = "kuhl_m_" ascii wide
    condition:
        2 of them
}

rule HackTool_LaZagne
{
    meta:
        description = "LaZagne - credential harvesting"
        author = "Haven Shield"
    strings:
        $a1 = "lazagne" ascii wide nocase
        $a2 = "AlessandroZ" ascii wide nocase
        $a3 = "laZagne" ascii wide
    condition:
        2 of them
}

rule HackTool_Rubeus
{
    meta:
        description = "Rubeus - Kerberos abuse toolkit"
        author = "Haven Shield"
    strings:
        $a1 = "Rubeus" ascii wide
        $a2 = "asktgt" ascii wide nocase
        $a3 = "kerberoast" ascii wide nocase
        $a4 = "ticket(s) for" ascii wide nocase
    condition:
        2 of them
}

rule HackTool_SharpHound
{
    meta:
        description = "SharpHound / BloodHound collector"
        author = "Haven Shield"
    strings:
        $a1 = "SharpHound" ascii wide
        $a2 = "BloodHound" ascii wide
        $a3 = "CollectionMethod" ascii wide
    condition:
        2 of them
}
