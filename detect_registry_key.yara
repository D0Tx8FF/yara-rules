rule detect_registry_key
{
    meta:
        author = "Islam Diab"
        description = "Detect registry key"
        date = "28-06-2026"
    strings:
        $reg = "SOFTWARE\\Borland\\Delphi\\RTL"
    condition:
        $reg
}