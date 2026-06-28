rule detect_openSSH_private_key
{
    meta:
        author = "Islam Diab"
        description = "Detect openSSH private key"
        date = "28-06-2026"
    strings:
        $file_signature = {2D 2D 2D 2D 2D 42 45 47 49 4E 20 4F 50 45 4E 53 53 48 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D}
        // Or use key
        //  $key = "-----BEGIN OPENSSH PRIVATE KEY-----"
    condition:
        $file_signature
        // $key
}