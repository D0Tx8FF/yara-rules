rule detect_domain
{
    meta:
        author = "Islam Diab"
        description = "Detect youtubedownloadernew.com domain"
        date = "28-06-2026"
    strings:
        $str1 = "youtubedownloadernew.com"
    condition:
        $str1
}