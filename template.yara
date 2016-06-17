
rule signature_name {
    meta:
        description = ""
        md5 = ""
        sha1 = ""
        filename = ""
        author = ""

	Block = true
	Log = true
	Quarantine = false

    strings:
        $string = { 00 }

    condition:
        IsPeFile and $string
}

