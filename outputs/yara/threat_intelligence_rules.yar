/*
    YARA Rules - Threat Intelligence Exercise
    Fecha: 2026-01-07
*/

rule Emotet_Network_Communication {
    meta:
        description = "Detecta comunicación de red asociada a Emotet"
        author = "Miguel Bercedo"
        date = "2026-01-07"
        severity = "high"
        
    strings:
        $ip1 = 104.236.185.25
        $ip2 = 108.167.189.16:58
        $ip3 = 46.16.58.148:25
        $ip4 = 184.106.54.10:25
        $ip5 = 98.136.96.80:25
        $ip6 = 198.23.53.42:25
        $ip7 = 40.97.121.2:587
        $ip8 = 208.84.244.49:25
    condition:
        any of them
}
