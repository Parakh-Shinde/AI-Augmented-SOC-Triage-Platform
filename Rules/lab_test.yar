rule AI_SOC_Bengin_Test
{
    meta:
        author = "Parakh Shinde"
        description = "Safe test rule for the AI SOC project"
        severity = "low"

    strings:
        $marker = "AI_SOC_YARA_TEST_2026" ascii wide nocase

    condition:
        $marker
}
