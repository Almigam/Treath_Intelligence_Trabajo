/*
    YARA Rules - Threat Intelligence Exercise
    Fecha: 2026-01-07
*/

rule Emotet_Network_Communication {
    meta:
        description = "Detecta comunicación de red asociada a Emotet"
        author = "Threat Intelligence Exercise - EUNEIZ"
        date = "2026-01-07"
        severity = "high"
        
    strings:
                $ip1 = "104.236.185.25"
        $ip2 = "108.167.189.16"
        $ip3 = "112.78.2.95"
        $ip4 = "173.201.193.101"
        $ip5 = "189.250.153.215"
        $ip6 = "190.10.194.42"
        $ip7 = "190.226.40.3"
        $ip8 = "200.68.61.242"
        $ip9 = "208.84.244.49"
        $ip10 = "50.87.153.168"
        
        
    condition:
        any of them
}
