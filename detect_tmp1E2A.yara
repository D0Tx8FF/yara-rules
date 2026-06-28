rule detect_tmp1E2A
{
    meta:
        author = "Islam Diab"
        description = "Detect tmp1E2A file"
        date = "28-06-2026"
    strings:
        $str1 = "tmp1E2A"
    condition:
        $str1
}