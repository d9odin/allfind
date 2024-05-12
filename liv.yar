rule living1 {

    strings:
        $s1 = "leap.bin"
        $s2 = "downloadfile"
        $s3 = "powershell"
    condition:
        ($s1) or ($s2) or ($s3)
}