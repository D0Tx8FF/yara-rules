rule detect_gif89a_over_50KB_in_size
{
    meta:
        author = "Islam Diab"
        description = "Detect GIF89a files greater than 50 KB"
        date = "28-06-2026"
    strings:
        $file_signature = {47 49 46 38 39 61}
    condition:
        $file_signature at 0 and
        filesize > 50KB
}