
/*
 * This will match any file containing "hello" anywhere.
 */
rule AsciiExample {
strings:
	// A string to match -- default is ascii
	$ascii_string = "hello"

condition:
	// The condition to match
	$ascii_string
}


/*
 * This will match any file containing unicode "hello" anywhere.
 */
rule UnicodeExample {
strings:
	// The 'wide' keyword indicates the string is unicode
	$unicode_string = "hello" wide

condition:
	$unicode_string
}


/*
 * Match any file containing the 01 23 45 67 89 AB CD EF byte sequence.
 */
rule HexExample {
	strings:
		// A few hex definitions demonstrating
		$hex_string1 = { 0123456789ABCDEF }
		$hex_string2 = { 0123456789abcdef }
		$hex_string3 = { 01 23 45 67 89 ab cd ef }
	
	condition:
		// Match any file containing 
		$hex_string1 or $hex_string2 or $hex_string3
}


/*
 * Match any file containing the 01 23 45 ?? ?? AB CD EF byte sequence.
 */
rule WildcardHexExample {
	strings:
		// A few hex definitions demonstrating
		$hex_string1 = { 012345????ABCDEF }
		$hex_string2 = { 012345????abcdef }
		$hex_string3 = { 01 23 45 ?? ?? ab cd ef }
	
	condition:
		// Match any file containing 
		$hex_string1 or $hex_string2 or $hex_string3
}


/*
 * Match any file containing "MZ" (not zero terminated) at offset 0.
 */
rule OffsetExample {
	strings:
		$mz = "MZ"

	condition:
		$mz at 0
}


/*
 * Match any file containing "PE" anywhere between offsets 32-100 (decimal)
 */
rule RangeExample {
	strings:
		$pe = "PE"
	
	condition:
		$pe in (32..100)
}


/*
 * Match any file with "PE" within 0x200 bytes (decimal) of the first occurrence of "MZ"
 */
rule RelativeOffsetExample {
	strings:
		$mz = "MZ"
		$pe = "PE"

	condition:
		$mz at 0 and $pe in (@mz[0]..0x200)
}


/*
 * Match any PE file as defined by MZ and PE signatures at required locations.
 */

rule IsPeFile {
	strings:
		$mz = "MZ"

	condition:
		$mz at 0 and uint32(uint32(0x3C)) == 0x4550
}


/*
 * Match any file with 55 8B EC (push ebp; mov ebp, esp) at the entry point.
 */
rule EntryPointExample {
	strings:
		$ep = { 55 8b ec }

	condition:
		$ep at entrypoint
}


/*
 * This will match any file containing "hello" anywhere.
 */
rule ConditionsExample {
strings:
	$string1 = "hello"
	$string2 = "hello"
	$string3 = "hello"
	

condition:
	any of them

	/*
	all of them
	1 of them

	any of ($string*)
	2 of ($string*)

	1 of ($string1,$string2)
	*/
}


/*
 * Any file containing at least 5 hello strings
 */
rule NumberStringsExample {
strings:
	$hello = "hello"

condition:
	#hello >= 5
}


/*
 * Match any file containing hello that is also a PE file
 */
rule RuleReference {
	strings:
		$hello = "hello"
	
	condition:
		$hello and IsPeFile
}


/*
 * Make YARA test only files less than 2MB for ALL rules.
 */
 global rule GlobalRuleExample {
 	condition:
		filesize < 2MB
}

