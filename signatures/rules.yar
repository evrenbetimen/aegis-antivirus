// Aegis demo signature rules (YARA subset supported by src/signatures.js).
// Turkish or English comments are both fine. // Türkçe yorum da serbesttir.
/*
 * Supported: text strings ("..." with nocase, ascii, wide, fullword), hex
 * strings ({ AA ?? A? [2-4] ( BB | CC ) ~DD }), conditions: and/or/not,
 * parentheses, $a, $a at N, #a, filesize (KB/MB), uint8/16/32[be](N),
 * arithmetic/bitwise operators, comparisons, any/all/none/N of them|($a*).
 * Rules using modules (pe, elf, math...), regex strings, `in`, `for` or rule
 * references are skipped (never mis-evaluated). xor/base64 modifiers are
 * tolerated: the plain string is searched.
 */

rule Ad_Ortasi {
  strings:
    $a = "zararli-ornek-metni" nocase
    $b = { 41 45 47 49 53 ?? 2D }
  condition:
    any of them
}

rule Demo_Test_Marker {
  strings:
    $m = "AEGIS-TEST-MARKER-V1" nocase
  condition:
    $m
}

rule Demo_Double_Keyword {
  strings:
    $cmd = "demo-powershell-launch" nocase
    $url = "demo-malicious.example" nocase
  condition:
    $cmd and $url
}

rule Demo_All_Parts {
  strings:
    $p1 = "demo-part-one"
    $p2 = "demo-part-two"
  condition:
    all of them
}

rule Demo_Paren_Or {
  strings:
    $a = "demo-alpha-token"
    $b = "demo-beta-token"
    $clean = "demo-trusted-stamp"
  condition:
    ($a or $b) and not $clean
}

rule Demo_Hex_Mz_Header {
  strings:
    $mz = { 4D 5A 90 00 ?? ?? 2D }
  condition:
    $mz
}

rule Demo_Repeated_Beacon {
  strings:
    $b = "demo-repeated-beacon"
  condition:
    #b == 3
}
