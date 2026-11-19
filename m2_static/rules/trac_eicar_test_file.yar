/*
    Harmless by design: the EICAR test file is a 68-byte, non-malicious string the
    industry agreed on so an engine can be exercised end to end. It is written as
    hex because the literal contains $, { and } - YARA modifier and delimiter
    characters that would otherwise need escaping.

    verdict "info": the sample is a test artefact, not a threat. TRAC scores
    nothing from this rule; M1's ClamAV pass and M5's own signature factor already
    cover it. It exists to prove the match -> metadata -> report path works.
*/
rule TRAC_EICAR_Anti_Malware_Test_File : test_signature
{
    meta:
        author = "TRAC"
        description = "EICAR standard antivirus test file"
        verdict = "info"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }

    condition:
        $eicar
}
