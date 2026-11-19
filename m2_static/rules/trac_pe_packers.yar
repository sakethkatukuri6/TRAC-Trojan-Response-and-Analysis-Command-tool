/*
    Tool identification, not threat identification.

    These are the section-name strings a packer or protector writes into its own
    output. Matching one says "this container was produced by that tool", which is
    a factual claim about bytes in the file. It does not say the file is malicious,
    so every rule here carries verdict "info" and no family: UPX alone ships more
    legitimate freeware than malware.

    Section names are matched as raw bytes rather than through YARA's `pe` module so
    the ruleset compiles against a yara-python build without PE support.
*/

rule TRAC_PE_Packed_UPX : packer
{
    meta:
        author = "TRAC"
        description = "UPX writes UPX0/UPX1 section names and an UPX! banner"
        verdict = "info"
        tool = "UPX"

    strings:
        $banner = "UPX!" ascii
        $s0 = "UPX0" ascii
        $s1 = "UPX1" ascii

    condition:
        $banner or ($s0 and $s1)
}

rule TRAC_PE_Packed_ASPack : packer
{
    meta:
        author = "TRAC"
        description = "ASPack writes .aspack and its .adata data section"
        verdict = "info"
        tool = "ASPack"

    strings:
        $a = ".aspack" ascii
        $b = ".adata" ascii

    condition:
        any of them
}

rule TRAC_PE_Packed_MPRESS : packer
{
    meta:
        author = "TRAC"
        description = "MPRESS writes MPRESS1/MPRESS2 section names"
        verdict = "info"
        tool = "MPRESS"

    strings:
        $a = "MPRESS1" ascii
        $b = "MPRESS2" ascii

    condition:
        any of them
}

rule TRAC_PE_Packed_Petite : packer
{
    meta:
        author = "TRAC"
        description = "Petite writes a .petite section"
        verdict = "info"
        tool = "Petite"

    strings:
        $a = ".petite" ascii wide

    condition:
        $a
}

rule TRAC_PE_Protected_VMProtect : protector
{
    meta:
        author = "TRAC"
        description = "VMProtect writes .vmp0/.vmp1 section names"
        verdict = "info"
        tool = "VMProtect"

    strings:
        $a = ".vmp0" ascii
        $b = ".vmp1" ascii

    condition:
        any of them
}
