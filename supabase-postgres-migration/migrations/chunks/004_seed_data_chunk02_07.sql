INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-221' AS parent_code, 'union' AS area_type, 'Dhopakhali' AS name, 'BD-UNION-2001' AS code
  UNION ALL
    SELECT 'BD-UPZ-221' AS parent_code, 'union' AS area_type, 'Moghia' AS name, 'BD-UNION-2002' AS code
  UNION ALL
    SELECT 'BD-UPZ-221' AS parent_code, 'union' AS area_type, 'Kachua' AS name, 'BD-UNION-2003' AS code
  UNION ALL
    SELECT 'BD-UPZ-221' AS parent_code, 'union' AS area_type, 'Gopalpur' AS name, 'BD-UNION-2004' AS code
  UNION ALL
    SELECT 'BD-UPZ-221' AS parent_code, 'union' AS area_type, 'Raripara' AS name, 'BD-UNION-2005' AS code
  UNION ALL
    SELECT 'BD-UPZ-221' AS parent_code, 'union' AS area_type, 'Badhal' AS name, 'BD-UNION-2006' AS code
  UNION ALL
    SELECT 'BD-UPZ-222' AS parent_code, 'union' AS area_type, 'Burrirdangga' AS name, 'BD-UNION-2007' AS code
  UNION ALL
    SELECT 'BD-UPZ-222' AS parent_code, 'union' AS area_type, 'Mithakhali' AS name, 'BD-UNION-2008' AS code
  UNION ALL
    SELECT 'BD-UPZ-222' AS parent_code, 'union' AS area_type, 'Sonailtala' AS name, 'BD-UNION-2009' AS code
  UNION ALL
    SELECT 'BD-UPZ-222' AS parent_code, 'union' AS area_type, 'Chadpai' AS name, 'BD-UNION-2010' AS code
  UNION ALL
    SELECT 'BD-UPZ-222' AS parent_code, 'union' AS area_type, 'Chila' AS name, 'BD-UNION-2011' AS code
  UNION ALL
    SELECT 'BD-UPZ-222' AS parent_code, 'union' AS area_type, 'Sundarban' AS name, 'BD-UNION-2012' AS code
  UNION ALL
    SELECT 'BD-UPZ-223' AS parent_code, 'union' AS area_type, 'Barobaria' AS name, 'BD-UNION-2013' AS code
  UNION ALL
    SELECT 'BD-UPZ-223' AS parent_code, 'union' AS area_type, 'Kalatala' AS name, 'BD-UNION-2014' AS code
  UNION ALL
    SELECT 'BD-UPZ-223' AS parent_code, 'union' AS area_type, 'Hizla' AS name, 'BD-UNION-2015' AS code
  UNION ALL
    SELECT 'BD-UPZ-223' AS parent_code, 'union' AS area_type, 'Shibpur' AS name, 'BD-UNION-2016' AS code
  UNION ALL
    SELECT 'BD-UPZ-223' AS parent_code, 'union' AS area_type, 'Chitalmari' AS name, 'BD-UNION-2017' AS code
  UNION ALL
    SELECT 'BD-UPZ-223' AS parent_code, 'union' AS area_type, 'Charbaniri' AS name, 'BD-UNION-2018' AS code
  UNION ALL
    SELECT 'BD-UPZ-223' AS parent_code, 'union' AS area_type, 'Shantoshpur' AS name, 'BD-UNION-2019' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Sadhuhati' AS name, 'BD-UNION-2020' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Modhuhati' AS name, 'BD-UNION-2021' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Saganna' AS name, 'BD-UNION-2022' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Halidhani' AS name, 'BD-UNION-2023' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Kumrabaria' AS name, 'BD-UNION-2024' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Ganna' AS name, 'BD-UNION-2025' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Maharazpur' AS name, 'BD-UNION-2026' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Paglakanai' AS name, 'BD-UNION-2027' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Porahati' AS name, 'BD-UNION-2028' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Harishongkorpur' AS name, 'BD-UNION-2029' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Padmakar' AS name, 'BD-UNION-2030' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Dogachhi' AS name, 'BD-UNION-2031' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Furshondi' AS name, 'BD-UNION-2032' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Ghorshal' AS name, 'BD-UNION-2033' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Kalicharanpur' AS name, 'BD-UNION-2034' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Surat' AS name, 'BD-UNION-2035' AS code
  UNION ALL
    SELECT 'BD-UPZ-224' AS parent_code, 'union' AS area_type, 'Naldanga' AS name, 'BD-UNION-2036' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Tribeni' AS name, 'BD-UNION-2037' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Mirzapur' AS name, 'BD-UNION-2038' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Dignagore' AS name, 'BD-UNION-2039' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Kancherkol' AS name, 'BD-UNION-2040' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Sarutia' AS name, 'BD-UNION-2041' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Hakimpur' AS name, 'BD-UNION-2042' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Dhaloharachandra' AS name, 'BD-UNION-2043' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Manoharpur' AS name, 'BD-UNION-2044' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Bogura' AS name, 'BD-UNION-2045' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Abaipur' AS name, 'BD-UNION-2046' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Nityanandapur' AS name, 'BD-UNION-2047' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Umedpur' AS name, 'BD-UNION-2048' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Dudshar' AS name, 'BD-UNION-2049' AS code
  UNION ALL
    SELECT 'BD-UPZ-225' AS parent_code, 'union' AS area_type, 'Fulhari' AS name, 'BD-UNION-2050' AS code
  UNION ALL
    SELECT 'BD-UPZ-226' AS parent_code, 'union' AS area_type, 'Bhayna' AS name, 'BD-UNION-2051' AS code
  UNION ALL
    SELECT 'BD-UPZ-226' AS parent_code, 'union' AS area_type, 'Joradah' AS name, 'BD-UNION-2052' AS code
  UNION ALL
    SELECT 'BD-UPZ-226' AS parent_code, 'union' AS area_type, 'Taherhuda' AS name, 'BD-UNION-2053' AS code
  UNION ALL
    SELECT 'BD-UPZ-226' AS parent_code, 'union' AS area_type, 'Daulatpur' AS name, 'BD-UNION-2054' AS code
  UNION ALL
    SELECT 'BD-UPZ-226' AS parent_code, 'union' AS area_type, 'Kapashatia' AS name, 'BD-UNION-2055' AS code
  UNION ALL
    SELECT 'BD-UPZ-226' AS parent_code, 'union' AS area_type, 'Falsi' AS name, 'BD-UNION-2056' AS code
  UNION ALL
    SELECT 'BD-UPZ-226' AS parent_code, 'union' AS area_type, 'Raghunathpur' AS name, 'BD-UNION-2057' AS code
  UNION ALL
    SELECT 'BD-UPZ-226' AS parent_code, 'union' AS area_type, 'Chandpur' AS name, 'BD-UNION-2058' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Sundarpurdurgapur' AS name, 'BD-UNION-2059' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Jamal' AS name, 'BD-UNION-2060' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Kola' AS name, 'BD-UNION-2061' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Niamatpur' AS name, 'BD-UNION-2062' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Simla-Rokonpur' AS name, 'BD-UNION-2063' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Trilochanpur' AS name, 'BD-UNION-2064' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Raygram' AS name, 'BD-UNION-2065' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Maliat' AS name, 'BD-UNION-2066' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Barabazar' AS name, 'BD-UNION-2067' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Kashtabhanga' AS name, 'BD-UNION-2068' AS code
  UNION ALL
    SELECT 'BD-UPZ-227' AS parent_code, 'union' AS area_type, 'Rakhalgachhi' AS name, 'BD-UNION-2069' AS code
  UNION ALL
    SELECT 'BD-UPZ-228' AS parent_code, 'union' AS area_type, 'Sabdalpur' AS name, 'BD-UNION-2070' AS code
  UNION ALL
    SELECT 'BD-UPZ-228' AS parent_code, 'union' AS area_type, 'Dora' AS name, 'BD-UNION-2071' AS code
  UNION ALL
    SELECT 'BD-UPZ-228' AS parent_code, 'union' AS area_type, 'Kushna' AS name, 'BD-UNION-2072' AS code
  UNION ALL
    SELECT 'BD-UPZ-228' AS parent_code, 'union' AS area_type, 'Baluhar' AS name, 'BD-UNION-2073' AS code
  UNION ALL
    SELECT 'BD-UPZ-228' AS parent_code, 'union' AS area_type, 'Elangi' AS name, 'BD-UNION-2074' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Sbk' AS name, 'BD-UNION-2075' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Fatepur' AS name, 'BD-UNION-2076' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Panthapara' AS name, 'BD-UNION-2077' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Swaruppur' AS name, 'BD-UNION-2078' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Shyamkur' AS name, 'BD-UNION-2079' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Nepa' AS name, 'BD-UNION-2080' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Kazirber' AS name, 'BD-UNION-2081' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Banshbaria' AS name, 'BD-UNION-2082' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Jadabpur' AS name, 'BD-UNION-2083' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Natima' AS name, 'BD-UNION-2084' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Manderbaria' AS name, 'BD-UNION-2085' AS code
  UNION ALL
    SELECT 'BD-UPZ-229' AS parent_code, 'union' AS area_type, 'Azampur' AS name, 'BD-UNION-2086' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Basanda' AS name, 'BD-UNION-2087' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Binoykati' AS name, 'BD-UNION-2088' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Gabharamchandrapur' AS name, 'BD-UNION-2089' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Keora' AS name, 'BD-UNION-2090' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Kirtipasha' AS name, 'BD-UNION-2091' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Nabagram' AS name, 'BD-UNION-2092' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Nathullabad' AS name, 'BD-UNION-2093' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Ponabalia' AS name, 'BD-UNION-2094' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Sekherhat' AS name, 'BD-UNION-2095' AS code
  UNION ALL
    SELECT 'BD-UPZ-230' AS parent_code, 'union' AS area_type, 'Gabkhandhansiri' AS name, 'BD-UNION-2096' AS code
  UNION ALL
    SELECT 'BD-UPZ-231' AS parent_code, 'union' AS area_type, 'Amua' AS name, 'BD-UNION-2097' AS code
  UNION ALL
    SELECT 'BD-UPZ-231' AS parent_code, 'union' AS area_type, 'Awrabunia' AS name, 'BD-UNION-2098' AS code
  UNION ALL
    SELECT 'BD-UPZ-231' AS parent_code, 'union' AS area_type, 'Chenchrirampur' AS name, 'BD-UNION-2099' AS code
  UNION ALL
    SELECT 'BD-UPZ-231' AS parent_code, 'union' AS area_type, 'Kanthalia' AS name, 'BD-UNION-2100' AS code
  UNION ALL
    SELECT 'BD-UPZ-231' AS parent_code, 'union' AS area_type, 'Patikhalghata' AS name, 'BD-UNION-2101' AS code
  UNION ALL
    SELECT 'BD-UPZ-231' AS parent_code, 'union' AS area_type, 'Shaulajalia' AS name, 'BD-UNION-2102' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Subidpur' AS name, 'BD-UNION-2103' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Siddhakati' AS name, 'BD-UNION-2104' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Ranapasha' AS name, 'BD-UNION-2105' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Nachanmohal' AS name, 'BD-UNION-2106' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Mollahat' AS name, 'BD-UNION-2107' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Magar' AS name, 'BD-UNION-2108' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Kusanghal' AS name, 'BD-UNION-2109' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Kulkathi' AS name, 'BD-UNION-2110' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Dapdapia' AS name, 'BD-UNION-2111' AS code
  UNION ALL
    SELECT 'BD-UPZ-232' AS parent_code, 'union' AS area_type, 'Bharabpasha' AS name, 'BD-UNION-2112' AS code
  UNION ALL
    SELECT 'BD-UPZ-233' AS parent_code, 'union' AS area_type, 'Suktagarh' AS name, 'BD-UNION-2113' AS code
  UNION ALL
    SELECT 'BD-UPZ-233' AS parent_code, 'union' AS area_type, 'Saturia' AS name, 'BD-UNION-2114' AS code
  UNION ALL
    SELECT 'BD-UPZ-233' AS parent_code, 'union' AS area_type, 'Mathbari' AS name, 'BD-UNION-2115' AS code
  UNION ALL
    SELECT 'BD-UPZ-233' AS parent_code, 'union' AS area_type, 'Galua' AS name, 'BD-UNION-2116' AS code
  UNION ALL
    SELECT 'BD-UPZ-233' AS parent_code, 'union' AS area_type, 'Baraia' AS name, 'BD-UNION-2117' AS code
  UNION ALL
    SELECT 'BD-UPZ-233' AS parent_code, 'union' AS area_type, 'Rajapur' AS name, 'BD-UNION-2118' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Adabaria' AS name, 'BD-UNION-2119' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Bauphal' AS name, 'BD-UNION-2120' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Daspara' AS name, 'BD-UNION-2121' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Kalaiya' AS name, 'BD-UNION-2122' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Nawmala' AS name, 'BD-UNION-2123' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Najirpur' AS name, 'BD-UNION-2124' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Madanpura' AS name, 'BD-UNION-2125' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Boga' AS name, 'BD-UNION-2126' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Kanakdia' AS name, 'BD-UNION-2127' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Shurjamoni' AS name, 'BD-UNION-2128' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Keshabpur' AS name, 'BD-UNION-2129' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Dhulia' AS name, 'BD-UNION-2130' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Kalisuri' AS name, 'BD-UNION-2131' AS code
  UNION ALL
    SELECT 'BD-UPZ-234' AS parent_code, 'union' AS area_type, 'Kachipara' AS name, 'BD-UNION-2132' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Laukathi' AS name, 'BD-UNION-2133' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Lohalia' AS name, 'BD-UNION-2134' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Kamalapur' AS name, 'BD-UNION-2135' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Jainkathi' AS name, 'BD-UNION-2136' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Kalikapur' AS name, 'BD-UNION-2137' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Badarpur' AS name, 'BD-UNION-2138' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Itbaria' AS name, 'BD-UNION-2139' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Marichbunia' AS name, 'BD-UNION-2140' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Auliapur' AS name, 'BD-UNION-2141' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Chotobighai' AS name, 'BD-UNION-2142' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Borobighai' AS name, 'BD-UNION-2143' AS code
  UNION ALL
    SELECT 'BD-UPZ-235' AS parent_code, 'union' AS area_type, 'Madarbunia' AS name, 'BD-UNION-2144' AS code
  UNION ALL
    SELECT 'BD-UPZ-236' AS parent_code, 'union' AS area_type, 'Pangasia' AS name, 'BD-UNION-2145' AS code
  UNION ALL
    SELECT 'BD-UPZ-236' AS parent_code, 'union' AS area_type, 'Muradia' AS name, 'BD-UNION-2146' AS code
  UNION ALL
    SELECT 'BD-UPZ-236' AS parent_code, 'union' AS area_type, 'Labukhali' AS name, 'BD-UNION-2147' AS code
  UNION ALL
    SELECT 'BD-UPZ-236' AS parent_code, 'union' AS area_type, 'Angaria' AS name, 'BD-UNION-2148' AS code
  UNION ALL
    SELECT 'BD-UPZ-236' AS parent_code, 'union' AS area_type, 'Sreerampur' AS name, 'BD-UNION-2149' AS code
  UNION ALL
    SELECT 'BD-UPZ-237' AS parent_code, 'union' AS area_type, 'Bashbaria' AS name, 'BD-UNION-2150' AS code
  UNION ALL
    SELECT 'BD-UPZ-237' AS parent_code, 'union' AS area_type, 'Rangopaldi' AS name, 'BD-UNION-2151' AS code
  UNION ALL
    SELECT 'BD-UPZ-237' AS parent_code, 'union' AS area_type, 'Alipur' AS name, 'BD-UNION-2152' AS code
  UNION ALL
    SELECT 'BD-UPZ-237' AS parent_code, 'union' AS area_type, 'Betagi Shankipur' AS name, 'BD-UNION-2153' AS code
  UNION ALL
    SELECT 'BD-UPZ-237' AS parent_code, 'union' AS area_type, 'Dashmina' AS name, 'BD-UNION-2154' AS code
  UNION ALL
    SELECT 'BD-UPZ-237' AS parent_code, 'union' AS area_type, 'Baharampur' AS name, 'BD-UNION-2155' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Chakamaia' AS name, 'BD-UNION-2156' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Tiakhali' AS name, 'BD-UNION-2157' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Lalua' AS name, 'BD-UNION-2158' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Dhankhali' AS name, 'BD-UNION-2159' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Mithagonj' AS name, 'BD-UNION-2160' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Nilgonj' AS name, 'BD-UNION-2161' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Dulaser' AS name, 'BD-UNION-2162' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Latachapli' AS name, 'BD-UNION-2163' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Mahipur' AS name, 'BD-UNION-2164' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Dalbugonj' AS name, 'BD-UNION-2165' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Baliatali' AS name, 'BD-UNION-2166' AS code
  UNION ALL
    SELECT 'BD-UPZ-238' AS parent_code, 'union' AS area_type, 'Champapur' AS name, 'BD-UNION-2167' AS code
  UNION ALL
    SELECT 'BD-UPZ-239' AS parent_code, 'union' AS area_type, 'Madhabkhali' AS name, 'BD-UNION-2168' AS code
  UNION ALL
    SELECT 'BD-UPZ-239' AS parent_code, 'union' AS area_type, 'Mirzaganj' AS name, 'BD-UNION-2169' AS code
  UNION ALL
    SELECT 'BD-UPZ-239' AS parent_code, 'union' AS area_type, 'Amragachia' AS name, 'BD-UNION-2170' AS code
  UNION ALL
    SELECT 'BD-UPZ-239' AS parent_code, 'union' AS area_type, 'Deuli Subidkhali' AS name, 'BD-UNION-2171' AS code
  UNION ALL
    SELECT 'BD-UPZ-239' AS parent_code, 'union' AS area_type, 'Kakrabunia' AS name, 'BD-UNION-2172' AS code
  UNION ALL
    SELECT 'BD-UPZ-239' AS parent_code, 'union' AS area_type, 'Majidbaria' AS name, 'BD-UNION-2173' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Amkhola' AS name, 'BD-UNION-2174' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Golkhali' AS name, 'BD-UNION-2175' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Galachipa' AS name, 'BD-UNION-2176' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Panpatty' AS name, 'BD-UNION-2177' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Ratandi Taltali' AS name, 'BD-UNION-2178' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Dakua' AS name, 'BD-UNION-2179' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Chiknikandi' AS name, 'BD-UNION-2180' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Gazalia' AS name, 'BD-UNION-2181' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Charkajol' AS name, 'BD-UNION-2182' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Charbiswas' AS name, 'BD-UNION-2183' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Bakulbaria' AS name, 'BD-UNION-2184' AS code
  UNION ALL
    SELECT 'BD-UPZ-240' AS parent_code, 'union' AS area_type, 'Kalagachhia' AS name, 'BD-UNION-2185' AS code
  UNION ALL
    SELECT 'BD-UPZ-241' AS parent_code, 'union' AS area_type, 'Rangabali' AS name, 'BD-UNION-2186' AS code
  UNION ALL
    SELECT 'BD-UPZ-241' AS parent_code, 'union' AS area_type, 'Barobaisdia' AS name, 'BD-UNION-2187' AS code
  UNION ALL
    SELECT 'BD-UPZ-241' AS parent_code, 'union' AS area_type, 'Chattobaisdia' AS name, 'BD-UNION-2188' AS code
  UNION ALL
    SELECT 'BD-UPZ-241' AS parent_code, 'union' AS area_type, 'Charmontaz' AS name, 'BD-UNION-2189' AS code
  UNION ALL
    SELECT 'BD-UPZ-241' AS parent_code, 'union' AS area_type, 'Chalitabunia' AS name, 'BD-UNION-2190' AS code
  UNION ALL
    SELECT 'BD-UPZ-242' AS parent_code, 'union' AS area_type, 'Shikder Mallik' AS name, 'BD-UNION-2191' AS code
  UNION ALL
    SELECT 'BD-UPZ-242' AS parent_code, 'union' AS area_type, 'Kodomtala' AS name, 'BD-UNION-2192' AS code
  UNION ALL
    SELECT 'BD-UPZ-242' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-2193' AS code
  UNION ALL
    SELECT 'BD-UPZ-242' AS parent_code, 'union' AS area_type, 'Kolakhali' AS name, 'BD-UNION-2194' AS code
  UNION ALL
    SELECT 'BD-UPZ-242' AS parent_code, 'union' AS area_type, 'Tona' AS name, 'BD-UNION-2195' AS code
  UNION ALL
    SELECT 'BD-UPZ-242' AS parent_code, 'union' AS area_type, 'Shariktola' AS name, 'BD-UNION-2196' AS code
  UNION ALL
    SELECT 'BD-UPZ-242' AS parent_code, 'union' AS area_type, 'Shankorpasa' AS name, 'BD-UNION-2197' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Mativangga' AS name, 'BD-UNION-2198' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Malikhali' AS name, 'BD-UNION-2199' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Daulbari Dobra' AS name, 'BD-UNION-2200' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Dirgha' AS name, 'BD-UNION-2201' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Kolardoania' AS name, 'BD-UNION-2202' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Sriramkathi' AS name, 'BD-UNION-2203' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Shakhmatia' AS name, 'BD-UNION-2204' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Nazirpur Sadar' AS name, 'BD-UNION-2205' AS code
  UNION ALL
    SELECT 'BD-UPZ-243' AS parent_code, 'union' AS area_type, 'Shakharikathi' AS name, 'BD-UNION-2206' AS code
  UNION ALL
    SELECT 'BD-UPZ-244' AS parent_code, 'union' AS area_type, 'Sayna Rogunathpur' AS name, 'BD-UNION-2207' AS code
  UNION ALL
    SELECT 'BD-UPZ-244' AS parent_code, 'union' AS area_type, 'Amrazuri' AS name, 'BD-UNION-2208' AS code
  UNION ALL
    SELECT 'BD-UPZ-244' AS parent_code, 'union' AS area_type, 'Kawkhali Sadar' AS name, 'BD-UNION-2209' AS code
  UNION ALL
    SELECT 'BD-UPZ-244' AS parent_code, 'union' AS area_type, 'Chirapara' AS name, 'BD-UNION-2210' AS code
  UNION ALL
    SELECT 'BD-UPZ-244' AS parent_code, 'union' AS area_type, 'Shialkhathi' AS name, 'BD-UNION-2211' AS code
  UNION ALL
    SELECT 'BD-UPZ-245' AS parent_code, 'union' AS area_type, 'Balipara' AS name, 'BD-UNION-2212' AS code
  UNION ALL
    SELECT 'BD-UPZ-245' AS parent_code, 'union' AS area_type, 'Pattashi' AS name, 'BD-UNION-2213' AS code
  UNION ALL
    SELECT 'BD-UPZ-245' AS parent_code, 'union' AS area_type, 'Parerhat' AS name, 'BD-UNION-2214' AS code
  UNION ALL
    SELECT 'BD-UPZ-246' AS parent_code, 'union' AS area_type, 'Vitabaria' AS name, 'BD-UNION-2215' AS code
  UNION ALL
    SELECT 'BD-UPZ-246' AS parent_code, 'union' AS area_type, 'Nodmulla' AS name, 'BD-UNION-2216' AS code
  UNION ALL
    SELECT 'BD-UPZ-246' AS parent_code, 'union' AS area_type, 'Telikhali' AS name, 'BD-UNION-2217' AS code
  UNION ALL
    SELECT 'BD-UPZ-246' AS parent_code, 'union' AS area_type, 'Ekree' AS name, 'BD-UNION-2218' AS code
  UNION ALL
    SELECT 'BD-UPZ-246' AS parent_code, 'union' AS area_type, 'Dhaoa' AS name, 'BD-UNION-2219' AS code
  UNION ALL
    SELECT 'BD-UPZ-246' AS parent_code, 'union' AS area_type, 'Vandaria Sadar' AS name, 'BD-UNION-2220' AS code
  UNION ALL
    SELECT 'BD-UPZ-246' AS parent_code, 'union' AS area_type, 'Gouripur' AS name, 'BD-UNION-2221' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Tuskhali' AS name, 'BD-UNION-2222' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Dhanisafa' AS name, 'BD-UNION-2223' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Mirukhali' AS name, 'BD-UNION-2224' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Tikikata' AS name, 'BD-UNION-2225' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Betmor Rajpara' AS name, 'BD-UNION-2226' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Amragachia' AS name, 'BD-UNION-2227' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Shapleza' AS name, 'BD-UNION-2228' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Daudkhali' AS name, 'BD-UNION-2229' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Mathbaria' AS name, 'BD-UNION-2230' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Baramasua' AS name, 'BD-UNION-2231' AS code
  UNION ALL
    SELECT 'BD-UPZ-247' AS parent_code, 'union' AS area_type, 'Haltagulishakhali' AS name, 'BD-UNION-2232' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Boldia' AS name, 'BD-UNION-2233' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Sohagdal' AS name, 'BD-UNION-2234' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Atghorkuriana' AS name, 'BD-UNION-2235' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Jolabari' AS name, 'BD-UNION-2236' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Doyhary' AS name, 'BD-UNION-2237' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Guarekha' AS name, 'BD-UNION-2238' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Somudoykathi' AS name, 'BD-UNION-2239' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Sutiakathi' AS name, 'BD-UNION-2240' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Sarengkathi' AS name, 'BD-UNION-2241' AS code
  UNION ALL
    SELECT 'BD-UPZ-248' AS parent_code, 'union' AS area_type, 'Shorupkathi' AS name, 'BD-UNION-2242' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Raipasha Karapur' AS name, 'BD-UNION-2243' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Kashipur' AS name, 'BD-UNION-2244' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Charbaria' AS name, 'BD-UNION-2245' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Shyastabad' AS name, 'BD-UNION-2246' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Charmonai' AS name, 'BD-UNION-2247' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Zagua' AS name, 'BD-UNION-2248' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Charcowa' AS name, 'BD-UNION-2249' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Chandpura' AS name, 'BD-UNION-2250' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Tungibaria' AS name, 'BD-UNION-2251' AS code
  UNION ALL
    SELECT 'BD-UPZ-249' AS parent_code, 'union' AS area_type, 'Chandramohan' AS name, 'BD-UNION-2252' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Charamaddi' AS name, 'BD-UNION-2253' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Charade' AS name, 'BD-UNION-2254' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Darial' AS name, 'BD-UNION-2255' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Dudhal' AS name, 'BD-UNION-2256' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Durgapasha' AS name, 'BD-UNION-2257' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Faridpur' AS name, 'BD-UNION-2258' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Kabai' AS name, 'BD-UNION-2259' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Nalua' AS name, 'BD-UNION-2260' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Kalashkathi' AS name, 'BD-UNION-2261' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Garuria' AS name, 'BD-UNION-2262' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Bharpasha' AS name, 'BD-UNION-2263' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Rangasree' AS name, 'BD-UNION-2264' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Padreeshibpur' AS name, 'BD-UNION-2265' AS code
  UNION ALL
    SELECT 'BD-UPZ-250' AS parent_code, 'union' AS area_type, 'Niamoti' AS name, 'BD-UNION-2266' AS code
  UNION ALL
    SELECT 'BD-UPZ-251' AS parent_code, 'union' AS area_type, 'Jahangir Nagar' AS name, 'BD-UNION-2267' AS code
  UNION ALL
    SELECT 'BD-UPZ-251' AS parent_code, 'union' AS area_type, 'Kaderpur' AS name, 'BD-UNION-2268' AS code
  UNION ALL
    SELECT 'BD-UPZ-251' AS parent_code, 'union' AS area_type, 'Deherhoti' AS name, 'BD-UNION-2269' AS code
  UNION ALL
    SELECT 'BD-UPZ-251' AS parent_code, 'union' AS area_type, 'Chandpasha' AS name, 'BD-UNION-2270' AS code
  UNION ALL
    SELECT 'BD-UPZ-251' AS parent_code, 'union' AS area_type, 'Rahamtpur' AS name, 'BD-UNION-2271' AS code
  UNION ALL
    SELECT 'BD-UPZ-251' AS parent_code, 'union' AS area_type, 'Madhbpasha' AS name, 'BD-UNION-2272' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Shatla' AS name, 'BD-UNION-2273' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Harta' AS name, 'BD-UNION-2274' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Jalla' AS name, 'BD-UNION-2275' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Otra' AS name, 'BD-UNION-2276' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Sholok' AS name, 'BD-UNION-2277' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Barakhota' AS name, 'BD-UNION-2278' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Bamrail' AS name, 'BD-UNION-2279' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Shikerpur Wazirpur' AS name, 'BD-UNION-2280' AS code
  UNION ALL
    SELECT 'BD-UPZ-252' AS parent_code, 'union' AS area_type, 'Gouthia' AS name, 'BD-UNION-2281' AS code
  UNION ALL
    SELECT 'BD-UPZ-253' AS parent_code, 'union' AS area_type, 'Bisharkandi' AS name, 'BD-UNION-2282' AS code
  UNION ALL
    SELECT 'BD-UPZ-253' AS parent_code, 'union' AS area_type, 'Illuhar' AS name, 'BD-UNION-2283' AS code
  UNION ALL
    SELECT 'BD-UPZ-253' AS parent_code, 'union' AS area_type, 'Sayedkathi' AS name, 'BD-UNION-2284' AS code
  UNION ALL
    SELECT 'BD-UPZ-253' AS parent_code, 'union' AS area_type, 'Chakhar' AS name, 'BD-UNION-2285' AS code
  UNION ALL
    SELECT 'BD-UPZ-253' AS parent_code, 'union' AS area_type, 'Saliabakpur' AS name, 'BD-UNION-2286' AS code
  UNION ALL
    SELECT 'BD-UPZ-253' AS parent_code, 'union' AS area_type, 'Baishari' AS name, 'BD-UNION-2287' AS code
  UNION ALL
    SELECT 'BD-UPZ-253' AS parent_code, 'union' AS area_type, 'Banaripara' AS name, 'BD-UNION-2288' AS code
  UNION ALL
    SELECT 'BD-UPZ-253' AS parent_code, 'union' AS area_type, 'Udykhati' AS name, 'BD-UNION-2289' AS code
  UNION ALL
    SELECT 'BD-UPZ-254' AS parent_code, 'union' AS area_type, 'Khanjapur' AS name, 'BD-UNION-2290' AS code
  UNION ALL
    SELECT 'BD-UPZ-254' AS parent_code, 'union' AS area_type, 'Barthi' AS name, 'BD-UNION-2291' AS code
  UNION ALL
    SELECT 'BD-UPZ-254' AS parent_code, 'union' AS area_type, 'Chandshi' AS name, 'BD-UNION-2292' AS code
  UNION ALL
    SELECT 'BD-UPZ-254' AS parent_code, 'union' AS area_type, 'Mahilara' AS name, 'BD-UNION-2293' AS code
  UNION ALL
    SELECT 'BD-UPZ-254' AS parent_code, 'union' AS area_type, 'Nalchira' AS name, 'BD-UNION-2294' AS code
  UNION ALL
    SELECT 'BD-UPZ-254' AS parent_code, 'union' AS area_type, 'Batajore' AS name, 'BD-UNION-2295' AS code
  UNION ALL
    SELECT 'BD-UPZ-254' AS parent_code, 'union' AS area_type, 'Sarikal' AS name, 'BD-UNION-2296' AS code
  UNION ALL
    SELECT 'BD-UPZ-255' AS parent_code, 'union' AS area_type, 'Rajihar' AS name, 'BD-UNION-2297' AS code
  UNION ALL
    SELECT 'BD-UPZ-255' AS parent_code, 'union' AS area_type, 'Bakal' AS name, 'BD-UNION-2298' AS code
  UNION ALL
    SELECT 'BD-UPZ-255' AS parent_code, 'union' AS area_type, 'Bagdha' AS name, 'BD-UNION-2299' AS code
  UNION ALL
    SELECT 'BD-UPZ-255' AS parent_code, 'union' AS area_type, 'Goila' AS name, 'BD-UNION-2300' AS code
  UNION ALL
    SELECT 'BD-UPZ-255' AS parent_code, 'union' AS area_type, 'Ratnapur' AS name, 'BD-UNION-2301' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Andarmanik' AS name, 'BD-UNION-2302' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Lata' AS name, 'BD-UNION-2303' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Charakkorea' AS name, 'BD-UNION-2304' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Ulania' AS name, 'BD-UNION-2305' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Mehendigong' AS name, 'BD-UNION-2306' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Biddanandapur' AS name, 'BD-UNION-2307' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Bhashanchar' AS name, 'BD-UNION-2308' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Jangalia' AS name, 'BD-UNION-2309' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Alimabad' AS name, 'BD-UNION-2310' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Chandpur' AS name, 'BD-UNION-2311' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Darirchar Khajuria' AS name, 'BD-UNION-2312' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Gobindapur' AS name, 'BD-UNION-2313' AS code
  UNION ALL
    SELECT 'BD-UPZ-256' AS parent_code, 'union' AS area_type, 'Chargopalpur' AS name, 'BD-UNION-2314' AS code
  UNION ALL
    SELECT 'BD-UPZ-257' AS parent_code, 'union' AS area_type, 'Batamara' AS name, 'BD-UNION-2315' AS code
  UNION ALL
    SELECT 'BD-UPZ-257' AS parent_code, 'union' AS area_type, 'Nazirpur' AS name, 'BD-UNION-2316' AS code
  UNION ALL
    SELECT 'BD-UPZ-257' AS parent_code, 'union' AS area_type, 'Safipur' AS name, 'BD-UNION-2317' AS code
  UNION ALL
    SELECT 'BD-UPZ-257' AS parent_code, 'union' AS area_type, 'Gaschua' AS name, 'BD-UNION-2318' AS code
  UNION ALL
    SELECT 'BD-UPZ-257' AS parent_code, 'union' AS area_type, 'Charkalekha' AS name, 'BD-UNION-2319' AS code
  UNION ALL
    SELECT 'BD-UPZ-257' AS parent_code, 'union' AS area_type, 'Muladi' AS name, 'BD-UNION-2320' AS code
  UNION ALL
    SELECT 'BD-UPZ-257' AS parent_code, 'union' AS area_type, 'Kazirchar' AS name, 'BD-UNION-2321' AS code
  UNION ALL
    SELECT 'BD-UPZ-258' AS parent_code, 'union' AS area_type, 'Harinathpur' AS name, 'BD-UNION-2322' AS code
  UNION ALL
    SELECT 'BD-UPZ-258' AS parent_code, 'union' AS area_type, 'Memania' AS name, 'BD-UNION-2323' AS code
  UNION ALL
    SELECT 'BD-UPZ-258' AS parent_code, 'union' AS area_type, 'Guabaria' AS name, 'BD-UNION-2324' AS code
  UNION ALL
    SELECT 'BD-UPZ-258' AS parent_code, 'union' AS area_type, 'Barjalia' AS name, 'BD-UNION-2325' AS code
  UNION ALL
    SELECT 'BD-UPZ-258' AS parent_code, 'union' AS area_type, 'Hizla Gourabdi' AS name, 'BD-UNION-2326' AS code
  UNION ALL
    SELECT 'BD-UPZ-258' AS parent_code, 'union' AS area_type, 'Dhulkhola' AS name, 'BD-UNION-2327' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Razapur' AS name, 'BD-UNION-2328' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Ilisha' AS name, 'BD-UNION-2329' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Westilisa' AS name, 'BD-UNION-2330' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Kachia' AS name, 'BD-UNION-2331' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Bapta' AS name, 'BD-UNION-2332' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Dhania' AS name, 'BD-UNION-2333' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Shibpur' AS name, 'BD-UNION-2334' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Alinagor' AS name, 'BD-UNION-2335' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Charshamya' AS name, 'BD-UNION-2336' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Vhelumia' AS name, 'BD-UNION-2337' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'Vheduria' AS name, 'BD-UNION-2338' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'North Digholdi' AS name, 'BD-UNION-2339' AS code
  UNION ALL
    SELECT 'BD-UPZ-259' AS parent_code, 'union' AS area_type, 'South Digholdi' AS name, 'BD-UNION-2340' AS code
  UNION ALL
    SELECT 'BD-UPZ-260' AS parent_code, 'union' AS area_type, 'Boromanika' AS name, 'BD-UNION-2341' AS code
  UNION ALL
    SELECT 'BD-UPZ-260' AS parent_code, 'union' AS area_type, 'Deula' AS name, 'BD-UNION-2342' AS code
  UNION ALL
    SELECT 'BD-UPZ-260' AS parent_code, 'union' AS area_type, 'Kutuba' AS name, 'BD-UNION-2343' AS code
  UNION ALL
    SELECT 'BD-UPZ-260' AS parent_code, 'union' AS area_type, 'Pakshia' AS name, 'BD-UNION-2344' AS code
  UNION ALL
    SELECT 'BD-UPZ-260' AS parent_code, 'union' AS area_type, 'Kachia' AS name, 'BD-UNION-2345' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Osmangonj' AS name, 'BD-UNION-2346' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Aslampur' AS name, 'BD-UNION-2347' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Zinnagor' AS name, 'BD-UNION-2348' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Aminabad' AS name, 'BD-UNION-2349' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Nilkomol' AS name, 'BD-UNION-2350' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Charmadraj' AS name, 'BD-UNION-2351' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Awajpur' AS name, 'BD-UNION-2352' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Awajpur #2353' AS name, 'BD-UNION-2353' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Charkolmi' AS name, 'BD-UNION-2354' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Charmanika' AS name, 'BD-UNION-2355' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Hazarigonj' AS name, 'BD-UNION-2356' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Jahanpur' AS name, 'BD-UNION-2357' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Nurabad' AS name, 'BD-UNION-2358' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Rasulpur' AS name, 'BD-UNION-2359' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Kukrimukri' AS name, 'BD-UNION-2360' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Abubakarpur' AS name, 'BD-UNION-2361' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Abdullahpur' AS name, 'BD-UNION-2362' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Nazrulnagar' AS name, 'BD-UNION-2363' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Mujibnagar' AS name, 'BD-UNION-2364' AS code
  UNION ALL
    SELECT 'BD-UPZ-261' AS parent_code, 'union' AS area_type, 'Dalchar' AS name, 'BD-UNION-2365' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'Madanpur' AS name, 'BD-UNION-2366' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'Madua' AS name, 'BD-UNION-2367' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'Charpata' AS name, 'BD-UNION-2368' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'North Joy Nagar' AS name, 'BD-UNION-2369' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'South Joy Nagar' AS name, 'BD-UNION-2370' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'Char Khalipa' AS name, 'BD-UNION-2371' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'Sayedpur' AS name, 'BD-UNION-2372' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'Hazipur' AS name, 'BD-UNION-2373' AS code
  UNION ALL
    SELECT 'BD-UPZ-262' AS parent_code, 'union' AS area_type, 'Vhovanipur' AS name, 'BD-UNION-2374' AS code
  UNION ALL
    SELECT 'BD-UPZ-263' AS parent_code, 'union' AS area_type, 'Hazirhat' AS name, 'BD-UNION-2375' AS code
  UNION ALL
    SELECT 'BD-UPZ-263' AS parent_code, 'union' AS area_type, 'Monpura' AS name, 'BD-UNION-2376' AS code
  UNION ALL
    SELECT 'BD-UPZ-263' AS parent_code, 'union' AS area_type, 'North Sakuchia' AS name, 'BD-UNION-2377' AS code
  UNION ALL
    SELECT 'BD-UPZ-263' AS parent_code, 'union' AS area_type, 'South Sakuchia' AS name, 'BD-UNION-2378' AS code
  UNION ALL
    SELECT 'BD-UPZ-264' AS parent_code, 'union' AS area_type, 'Chanchra' AS name, 'BD-UNION-2379' AS code
  UNION ALL
    SELECT 'BD-UPZ-264' AS parent_code, 'union' AS area_type, 'Shambupur' AS name, 'BD-UNION-2380' AS code
  UNION ALL
    SELECT 'BD-UPZ-264' AS parent_code, 'union' AS area_type, 'Sonapur' AS name, 'BD-UNION-2381' AS code
  UNION ALL
    SELECT 'BD-UPZ-264' AS parent_code, 'union' AS area_type, 'Chadpur' AS name, 'BD-UNION-2382' AS code
  UNION ALL
    SELECT 'BD-UPZ-264' AS parent_code, 'union' AS area_type, 'Baro Molongchora' AS name, 'BD-UNION-2383' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Badarpur' AS name, 'BD-UNION-2384' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Charbhuta' AS name, 'BD-UNION-2385' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Kalma' AS name, 'BD-UNION-2386' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Dholigour Nagar' AS name, 'BD-UNION-2387' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Lalmohan' AS name, 'BD-UNION-2388' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Lord Hardinge' AS name, 'BD-UNION-2389' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Ramagonj' AS name, 'BD-UNION-2390' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Paschim Char Umed' AS name, 'BD-UNION-2391' AS code
  UNION ALL
    SELECT 'BD-UPZ-265' AS parent_code, 'union' AS area_type, 'Farajgonj' AS name, 'BD-UNION-2392' AS code
  UNION ALL
    SELECT 'BD-UPZ-266' AS parent_code, 'union' AS area_type, 'Amtali' AS name, 'BD-UNION-2393' AS code
  UNION ALL
    SELECT 'BD-UPZ-266' AS parent_code, 'union' AS area_type, 'Gulishakhali' AS name, 'BD-UNION-2394' AS code
  UNION ALL
    SELECT 'BD-UPZ-266' AS parent_code, 'union' AS area_type, 'Athrogasia' AS name, 'BD-UNION-2395' AS code
  UNION ALL
    SELECT 'BD-UPZ-266' AS parent_code, 'union' AS area_type, 'Kukua' AS name, 'BD-UNION-2396' AS code
  UNION ALL
    SELECT 'BD-UPZ-266' AS parent_code, 'union' AS area_type, 'Haldia' AS name, 'BD-UNION-2397' AS code
  UNION ALL
    SELECT 'BD-UPZ-266' AS parent_code, 'union' AS area_type, 'Chotobogi' AS name, 'BD-UNION-2398' AS code
  UNION ALL
    SELECT 'BD-UPZ-266' AS parent_code, 'union' AS area_type, 'Arpangasia' AS name, 'BD-UNION-2399' AS code
  UNION ALL
    SELECT 'BD-UPZ-266' AS parent_code, 'union' AS area_type, 'Chowra' AS name, 'BD-UNION-2400' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;