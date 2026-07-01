INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'M. Baliatali' AS name, 'BD-UNION-2401' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Noltona' AS name, 'BD-UNION-2402' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Bodorkhali' AS name, 'BD-UNION-2403' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Gowrichanna' AS name, 'BD-UNION-2404' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Fuljhuri' AS name, 'BD-UNION-2405' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Keorabunia' AS name, 'BD-UNION-2406' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Ayla Patakata' AS name, 'BD-UNION-2407' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Burirchor' AS name, 'BD-UNION-2408' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Dhalua' AS name, 'BD-UNION-2409' AS code
  UNION ALL
    SELECT 'BD-UPZ-267' AS parent_code, 'union' AS area_type, 'Barguna' AS name, 'BD-UNION-2410' AS code
  UNION ALL
    SELECT 'BD-UPZ-268' AS parent_code, 'union' AS area_type, 'Bibichini' AS name, 'BD-UNION-2411' AS code
  UNION ALL
    SELECT 'BD-UPZ-268' AS parent_code, 'union' AS area_type, 'Betagi' AS name, 'BD-UNION-2412' AS code
  UNION ALL
    SELECT 'BD-UPZ-268' AS parent_code, 'union' AS area_type, 'Hosnabad' AS name, 'BD-UNION-2413' AS code
  UNION ALL
    SELECT 'BD-UPZ-268' AS parent_code, 'union' AS area_type, 'Mokamia' AS name, 'BD-UNION-2414' AS code
  UNION ALL
    SELECT 'BD-UPZ-268' AS parent_code, 'union' AS area_type, 'Buramajumder' AS name, 'BD-UNION-2415' AS code
  UNION ALL
    SELECT 'BD-UPZ-268' AS parent_code, 'union' AS area_type, 'Kazirabad' AS name, 'BD-UNION-2416' AS code
  UNION ALL
    SELECT 'BD-UPZ-268' AS parent_code, 'union' AS area_type, 'Sarisamuri' AS name, 'BD-UNION-2417' AS code
  UNION ALL
    SELECT 'BD-UPZ-269' AS parent_code, 'union' AS area_type, 'Bukabunia' AS name, 'BD-UNION-2418' AS code
  UNION ALL
    SELECT 'BD-UPZ-269' AS parent_code, 'union' AS area_type, 'Bamna' AS name, 'BD-UNION-2419' AS code
  UNION ALL
    SELECT 'BD-UPZ-269' AS parent_code, 'union' AS area_type, 'Ramna' AS name, 'BD-UNION-2420' AS code
  UNION ALL
    SELECT 'BD-UPZ-269' AS parent_code, 'union' AS area_type, 'Doutola' AS name, 'BD-UNION-2421' AS code
  UNION ALL
    SELECT 'BD-UPZ-270' AS parent_code, 'union' AS area_type, 'Raihanpur' AS name, 'BD-UNION-2422' AS code
  UNION ALL
    SELECT 'BD-UPZ-270' AS parent_code, 'union' AS area_type, 'Nachnapara' AS name, 'BD-UNION-2423' AS code
  UNION ALL
    SELECT 'BD-UPZ-270' AS parent_code, 'union' AS area_type, 'Charduany' AS name, 'BD-UNION-2424' AS code
  UNION ALL
    SELECT 'BD-UPZ-270' AS parent_code, 'union' AS area_type, 'Patharghata' AS name, 'BD-UNION-2425' AS code
  UNION ALL
    SELECT 'BD-UPZ-270' AS parent_code, 'union' AS area_type, 'Kalmegha' AS name, 'BD-UNION-2426' AS code
  UNION ALL
    SELECT 'BD-UPZ-270' AS parent_code, 'union' AS area_type, 'Kakchira' AS name, 'BD-UNION-2427' AS code
  UNION ALL
    SELECT 'BD-UPZ-270' AS parent_code, 'union' AS area_type, 'Kathaltali' AS name, 'BD-UNION-2428' AS code
  UNION ALL
    SELECT 'BD-UPZ-271' AS parent_code, 'union' AS area_type, 'Karibaria' AS name, 'BD-UNION-2429' AS code
  UNION ALL
    SELECT 'BD-UPZ-271' AS parent_code, 'union' AS area_type, 'Panchakoralia' AS name, 'BD-UNION-2430' AS code
  UNION ALL
    SELECT 'BD-UPZ-271' AS parent_code, 'union' AS area_type, 'Barabagi' AS name, 'BD-UNION-2431' AS code
  UNION ALL
    SELECT 'BD-UPZ-271' AS parent_code, 'union' AS area_type, 'Chhotabagi' AS name, 'BD-UNION-2432' AS code
  UNION ALL
    SELECT 'BD-UPZ-271' AS parent_code, 'union' AS area_type, 'Nishanbaria' AS name, 'BD-UNION-2433' AS code
  UNION ALL
    SELECT 'BD-UPZ-271' AS parent_code, 'union' AS area_type, 'Sarikkhali' AS name, 'BD-UNION-2434' AS code
  UNION ALL
    SELECT 'BD-UPZ-271' AS parent_code, 'union' AS area_type, 'Sonakata' AS name, 'BD-UNION-2435' AS code
  UNION ALL
    SELECT 'BD-UPZ-284' AS parent_code, 'union' AS area_type, 'Tazpur' AS name, 'BD-UNION-2436' AS code
  UNION ALL
    SELECT 'BD-UPZ-284' AS parent_code, 'union' AS area_type, 'Umorpur' AS name, 'BD-UNION-2437' AS code
  UNION ALL
    SELECT 'BD-UPZ-284' AS parent_code, 'union' AS area_type, 'West Poilanpur' AS name, 'BD-UNION-2438' AS code
  UNION ALL
    SELECT 'BD-UPZ-272' AS parent_code, 'union' AS area_type, 'East Poilanpur' AS name, 'BD-UNION-2439' AS code
  UNION ALL
    SELECT 'BD-UPZ-272' AS parent_code, 'union' AS area_type, 'Boaljur' AS name, 'BD-UNION-2440' AS code
  UNION ALL
    SELECT 'BD-UPZ-284' AS parent_code, 'union' AS area_type, 'Burungabazar' AS name, 'BD-UNION-2441' AS code
  UNION ALL
    SELECT 'BD-UPZ-284' AS parent_code, 'union' AS area_type, 'Goalabazar' AS name, 'BD-UNION-2442' AS code
  UNION ALL
    SELECT 'BD-UPZ-284' AS parent_code, 'union' AS area_type, 'Doyamir' AS name, 'BD-UNION-2443' AS code
  UNION ALL
    SELECT 'BD-UPZ-284' AS parent_code, 'union' AS area_type, 'Usmanpur' AS name, 'BD-UNION-2444' AS code
  UNION ALL
    SELECT 'BD-UPZ-272' AS parent_code, 'union' AS area_type, 'Dewanbazar' AS name, 'BD-UNION-2445' AS code
  UNION ALL
    SELECT 'BD-UPZ-272' AS parent_code, 'union' AS area_type, 'West Gouripur' AS name, 'BD-UNION-2446' AS code
  UNION ALL
    SELECT 'BD-UPZ-272' AS parent_code, 'union' AS area_type, 'East Gouripur' AS name, 'BD-UNION-2447' AS code
  UNION ALL
    SELECT 'BD-UPZ-272' AS parent_code, 'union' AS area_type, 'Balaganj' AS name, 'BD-UNION-2448' AS code
  UNION ALL
    SELECT 'BD-UPZ-284' AS parent_code, 'union' AS area_type, 'Sadipur' AS name, 'BD-UNION-2449' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Tilpara' AS name, 'BD-UNION-2450' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Alinagar' AS name, 'BD-UNION-2451' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Charkhai' AS name, 'BD-UNION-2452' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Dubag' AS name, 'BD-UNION-2453' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Sheola' AS name, 'BD-UNION-2454' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Kurarbazar' AS name, 'BD-UNION-2455' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Mathiura' AS name, 'BD-UNION-2456' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Mullapur' AS name, 'BD-UNION-2457' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Muria' AS name, 'BD-UNION-2458' AS code
  UNION ALL
    SELECT 'BD-UPZ-273' AS parent_code, 'union' AS area_type, 'Lauta' AS name, 'BD-UNION-2459' AS code
  UNION ALL
    SELECT 'BD-UPZ-274' AS parent_code, 'union' AS area_type, 'Rampasha' AS name, 'BD-UNION-2460' AS code
  UNION ALL
    SELECT 'BD-UPZ-274' AS parent_code, 'union' AS area_type, 'Lamakazi' AS name, 'BD-UNION-2461' AS code
  UNION ALL
    SELECT 'BD-UPZ-274' AS parent_code, 'union' AS area_type, 'Khajanchi' AS name, 'BD-UNION-2462' AS code
  UNION ALL
    SELECT 'BD-UPZ-274' AS parent_code, 'union' AS area_type, 'Alankari' AS name, 'BD-UNION-2463' AS code
  UNION ALL
    SELECT 'BD-UPZ-274' AS parent_code, 'union' AS area_type, 'Dewkalash' AS name, 'BD-UNION-2464' AS code
  UNION ALL
    SELECT 'BD-UPZ-274' AS parent_code, 'union' AS area_type, 'Bishwanath' AS name, 'BD-UNION-2465' AS code
  UNION ALL
    SELECT 'BD-UPZ-274' AS parent_code, 'union' AS area_type, 'Doshghar' AS name, 'BD-UNION-2466' AS code
  UNION ALL
    SELECT 'BD-UPZ-274' AS parent_code, 'union' AS area_type, 'Daulatpur' AS name, 'BD-UNION-2467' AS code
  UNION ALL
    SELECT 'BD-UPZ-275' AS parent_code, 'union' AS area_type, 'Telikhal' AS name, 'BD-UNION-2468' AS code
  UNION ALL
    SELECT 'BD-UPZ-275' AS parent_code, 'union' AS area_type, 'Islampur Paschim' AS name, 'BD-UNION-2469' AS code
  UNION ALL
    SELECT 'BD-UPZ-275' AS parent_code, 'union' AS area_type, 'Islampur Purba' AS name, 'BD-UNION-2470' AS code
  UNION ALL
    SELECT 'BD-UPZ-275' AS parent_code, 'union' AS area_type, 'Isakalas' AS name, 'BD-UNION-2471' AS code
  UNION ALL
    SELECT 'BD-UPZ-275' AS parent_code, 'union' AS area_type, 'Uttor Ronikhai' AS name, 'BD-UNION-2472' AS code
  UNION ALL
    SELECT 'BD-UPZ-275' AS parent_code, 'union' AS area_type, 'Dakkin Ronikhai' AS name, 'BD-UNION-2473' AS code
  UNION ALL
    SELECT 'BD-UPZ-276' AS parent_code, 'union' AS area_type, 'Ghilachora' AS name, 'BD-UNION-2474' AS code
  UNION ALL
    SELECT 'BD-UPZ-276' AS parent_code, 'union' AS area_type, 'Fenchuganj' AS name, 'BD-UNION-2475' AS code
  UNION ALL
    SELECT 'BD-UPZ-276' AS parent_code, 'union' AS area_type, 'Uttar Kushiara' AS name, 'BD-UNION-2476' AS code
  UNION ALL
    SELECT 'BD-UPZ-276' AS parent_code, 'union' AS area_type, 'Uttar Fenchuganj' AS name, 'BD-UNION-2477' AS code
  UNION ALL
    SELECT 'BD-UPZ-276' AS parent_code, 'union' AS area_type, 'Maijgaon' AS name, 'BD-UNION-2478' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Golapganj' AS name, 'BD-UNION-2479' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Fulbari' AS name, 'BD-UNION-2480' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Lakshmipasha' AS name, 'BD-UNION-2481' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Budhbaribazar' AS name, 'BD-UNION-2482' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Dhakadakshin' AS name, 'BD-UNION-2483' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Sharifganj' AS name, 'BD-UNION-2484' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Uttar Badepasha' AS name, 'BD-UNION-2485' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Lakshanaband' AS name, 'BD-UNION-2486' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'Bhadeshwar' AS name, 'BD-UNION-2487' AS code
  UNION ALL
    SELECT 'BD-UPZ-277' AS parent_code, 'union' AS area_type, 'West Amura' AS name, 'BD-UNION-2488' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Fothepur' AS name, 'BD-UNION-2489' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Rustampur' AS name, 'BD-UNION-2490' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Paschim Jaflong' AS name, 'BD-UNION-2491' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Purba Jaflong' AS name, 'BD-UNION-2492' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Lengura' AS name, 'BD-UNION-2493' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Alirgaon' AS name, 'BD-UNION-2494' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Nandirgaon' AS name, 'BD-UNION-2495' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Towakul' AS name, 'BD-UNION-2496' AS code
  UNION ALL
    SELECT 'BD-UPZ-278' AS parent_code, 'union' AS area_type, 'Daubari' AS name, 'BD-UNION-2497' AS code
  UNION ALL
    SELECT 'BD-UPZ-279' AS parent_code, 'union' AS area_type, 'Nijpat' AS name, 'BD-UNION-2498' AS code
  UNION ALL
    SELECT 'BD-UPZ-279' AS parent_code, 'union' AS area_type, 'Jaintapur' AS name, 'BD-UNION-2499' AS code
  UNION ALL
    SELECT 'BD-UPZ-279' AS parent_code, 'union' AS area_type, 'Charikatha' AS name, 'BD-UNION-2500' AS code
  UNION ALL
    SELECT 'BD-UPZ-279' AS parent_code, 'union' AS area_type, 'Darbast' AS name, 'BD-UNION-2501' AS code
  UNION ALL
    SELECT 'BD-UPZ-279' AS parent_code, 'union' AS area_type, 'Fatehpur' AS name, 'BD-UNION-2502' AS code
  UNION ALL
    SELECT 'BD-UPZ-279' AS parent_code, 'union' AS area_type, 'Chiknagul' AS name, 'BD-UNION-2503' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Rajagonj' AS name, 'BD-UNION-2504' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Lakshiprashad Purbo' AS name, 'BD-UNION-2505' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Lakshiprashad Pashim' AS name, 'BD-UNION-2506' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Digirpar Purbo' AS name, 'BD-UNION-2507' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Satbakh' AS name, 'BD-UNION-2508' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Barachotul' AS name, 'BD-UNION-2509' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Kanaighat' AS name, 'BD-UNION-2510' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Dakhin Banigram' AS name, 'BD-UNION-2511' AS code
  UNION ALL
    SELECT 'BD-UPZ-280' AS parent_code, 'union' AS area_type, 'Jinghabari' AS name, 'BD-UNION-2512' AS code
  UNION ALL
    SELECT 'BD-UPZ-281' AS parent_code, 'union' AS area_type, 'Jalalabad' AS name, 'BD-UNION-2513' AS code
  UNION ALL
    SELECT 'BD-UPZ-281' AS parent_code, 'union' AS area_type, 'Hatkhula' AS name, 'BD-UNION-2514' AS code
  UNION ALL
    SELECT 'BD-UPZ-281' AS parent_code, 'union' AS area_type, 'Khadimnagar' AS name, 'BD-UNION-2515' AS code
  UNION ALL
    SELECT 'BD-UPZ-281' AS parent_code, 'union' AS area_type, 'Khadimpara' AS name, 'BD-UNION-2516' AS code
  UNION ALL
    SELECT 'BD-UPZ-281' AS parent_code, 'union' AS area_type, 'Tultikor' AS name, 'BD-UNION-2517' AS code
  UNION ALL
    SELECT 'BD-UPZ-281' AS parent_code, 'union' AS area_type, 'Tukerbazar' AS name, 'BD-UNION-2518' AS code
  UNION ALL
    SELECT 'BD-UPZ-281' AS parent_code, 'union' AS area_type, 'Mugolgaon' AS name, 'BD-UNION-2519' AS code
  UNION ALL
    SELECT 'BD-UPZ-281' AS parent_code, 'union' AS area_type, 'Kandigaon' AS name, 'BD-UNION-2520' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Manikpur' AS name, 'BD-UNION-2521' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Sultanpur' AS name, 'BD-UNION-2522' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Barohal' AS name, 'BD-UNION-2523' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Birorsri' AS name, 'BD-UNION-2524' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Kajalshah' AS name, 'BD-UNION-2525' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Kolachora' AS name, 'BD-UNION-2526' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Zakiganj' AS name, 'BD-UNION-2527' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Barothakuri' AS name, 'BD-UNION-2528' AS code
  UNION ALL
    SELECT 'BD-UPZ-282' AS parent_code, 'union' AS area_type, 'Kaskanakpur' AS name, 'BD-UNION-2529' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Lalabazar' AS name, 'BD-UNION-2530' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Moglabazar' AS name, 'BD-UNION-2531' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Boroikandi' AS name, 'BD-UNION-2532' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Silam' AS name, 'BD-UNION-2533' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Daudpur' AS name, 'BD-UNION-2534' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Mollargaon' AS name, 'BD-UNION-2535' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Kuchai' AS name, 'BD-UNION-2536' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Kamalbazar' AS name, 'BD-UNION-2537' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Jalalpur' AS name, 'BD-UNION-2538' AS code
  UNION ALL
    SELECT 'BD-UPZ-283' AS parent_code, 'union' AS area_type, 'Tetli' AS name, 'BD-UNION-2539' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Talimpur' AS name, 'BD-UNION-2540' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Borni' AS name, 'BD-UNION-2541' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Dasherbazar' AS name, 'BD-UNION-2542' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Nizbahadurpur' AS name, 'BD-UNION-2543' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Uttar Shahbajpur' AS name, 'BD-UNION-2544' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Dakkhin Shahbajpur' AS name, 'BD-UNION-2545' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Talimpur #2546' AS name, 'BD-UNION-2546' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Baralekha' AS name, 'BD-UNION-2547' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Dakshinbhag Uttar' AS name, 'BD-UNION-2548' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Dakshinbhag Dakkhin' AS name, 'BD-UNION-2549' AS code
  UNION ALL
    SELECT 'BD-UPZ-285' AS parent_code, 'union' AS area_type, 'Sujanagar' AS name, 'BD-UNION-2550' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Adampur' AS name, 'BD-UNION-2551' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Patanushar' AS name, 'BD-UNION-2552' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Madhabpur' AS name, 'BD-UNION-2553' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Rahimpur' AS name, 'BD-UNION-2554' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Shamshernagar' AS name, 'BD-UNION-2555' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Kamalgonj' AS name, 'BD-UNION-2556' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Islampur' AS name, 'BD-UNION-2557' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Munshibazar' AS name, 'BD-UNION-2558' AS code
  UNION ALL
    SELECT 'BD-UPZ-286' AS parent_code, 'union' AS area_type, 'Alinagar' AS name, 'BD-UNION-2559' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Baramchal' AS name, 'BD-UNION-2560' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Bhukshimail' AS name, 'BD-UNION-2561' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Joychandi' AS name, 'BD-UNION-2562' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Brammanbazar' AS name, 'BD-UNION-2563' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Kadipur' AS name, 'BD-UNION-2564' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Kulaura' AS name, 'BD-UNION-2565' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Rauthgaon' AS name, 'BD-UNION-2566' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Tilagaon' AS name, 'BD-UNION-2567' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Sharifpur' AS name, 'BD-UNION-2568' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Prithimpassa' AS name, 'BD-UNION-2569' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Kormodha' AS name, 'BD-UNION-2570' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Bhatera' AS name, 'BD-UNION-2571' AS code
  UNION ALL
    SELECT 'BD-UPZ-287' AS parent_code, 'union' AS area_type, 'Hazipur' AS name, 'BD-UNION-2572' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Amtail' AS name, 'BD-UNION-2573' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Khalilpur' AS name, 'BD-UNION-2574' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Monumukh' AS name, 'BD-UNION-2575' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Kamalpur' AS name, 'BD-UNION-2576' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Apar Kagabala' AS name, 'BD-UNION-2577' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Akhailkura' AS name, 'BD-UNION-2578' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Ekatuna' AS name, 'BD-UNION-2579' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Chadnighat' AS name, 'BD-UNION-2580' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Konokpur' AS name, 'BD-UNION-2581' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Nazirabad' AS name, 'BD-UNION-2582' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Mostafapur' AS name, 'BD-UNION-2583' AS code
  UNION ALL
    SELECT 'BD-UPZ-288' AS parent_code, 'union' AS area_type, 'Giasnagar' AS name, 'BD-UNION-2584' AS code
  UNION ALL
    SELECT 'BD-UPZ-289' AS parent_code, 'union' AS area_type, 'Fotepur' AS name, 'BD-UNION-2585' AS code
  UNION ALL
    SELECT 'BD-UPZ-289' AS parent_code, 'union' AS area_type, 'Uttorbhag' AS name, 'BD-UNION-2586' AS code
  UNION ALL
    SELECT 'BD-UPZ-289' AS parent_code, 'union' AS area_type, 'Munsibazar' AS name, 'BD-UNION-2587' AS code
  UNION ALL
    SELECT 'BD-UPZ-289' AS parent_code, 'union' AS area_type, 'Panchgaon' AS name, 'BD-UNION-2588' AS code
  UNION ALL
    SELECT 'BD-UPZ-289' AS parent_code, 'union' AS area_type, 'Rajnagar' AS name, 'BD-UNION-2589' AS code
  UNION ALL
    SELECT 'BD-UPZ-289' AS parent_code, 'union' AS area_type, 'Tengra' AS name, 'BD-UNION-2590' AS code
  UNION ALL
    SELECT 'BD-UPZ-289' AS parent_code, 'union' AS area_type, 'Kamarchak' AS name, 'BD-UNION-2591' AS code
  UNION ALL
    SELECT 'BD-UPZ-289' AS parent_code, 'union' AS area_type, 'Munsurnagar' AS name, 'BD-UNION-2592' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Mirzapur' AS name, 'BD-UNION-2593' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Bhunabir' AS name, 'BD-UNION-2594' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Sreemangal' AS name, 'BD-UNION-2595' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Sindurkhan' AS name, 'BD-UNION-2596' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Kalapur' AS name, 'BD-UNION-2597' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Ashidron' AS name, 'BD-UNION-2598' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Rajghat' AS name, 'BD-UNION-2599' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Kalighat' AS name, 'BD-UNION-2600' AS code
  UNION ALL
    SELECT 'BD-UPZ-290' AS parent_code, 'union' AS area_type, 'Satgaon' AS name, 'BD-UNION-2601' AS code
  UNION ALL
    SELECT 'BD-UPZ-291' AS parent_code, 'union' AS area_type, 'Jafornagar' AS name, 'BD-UNION-2602' AS code
  UNION ALL
    SELECT 'BD-UPZ-291' AS parent_code, 'union' AS area_type, 'West Juri' AS name, 'BD-UNION-2603' AS code
  UNION ALL
    SELECT 'BD-UPZ-291' AS parent_code, 'union' AS area_type, 'Gualbari' AS name, 'BD-UNION-2604' AS code
  UNION ALL
    SELECT 'BD-UPZ-291' AS parent_code, 'union' AS area_type, 'Sagornal' AS name, 'BD-UNION-2605' AS code
  UNION ALL
    SELECT 'BD-UPZ-291' AS parent_code, 'union' AS area_type, 'Fultola' AS name, 'BD-UNION-2606' AS code
  UNION ALL
    SELECT 'BD-UPZ-291' AS parent_code, 'union' AS area_type, 'Eastjuri' AS name, 'BD-UNION-2607' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Barabhakoir Paschim' AS name, 'BD-UNION-2608' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Barabhakoir Purba' AS name, 'BD-UNION-2609' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Inatganj' AS name, 'BD-UNION-2610' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Digholbak' AS name, 'BD-UNION-2611' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Aushkandi' AS name, 'BD-UNION-2612' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Kurshi' AS name, 'BD-UNION-2613' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Kargoan' AS name, 'BD-UNION-2614' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Nabiganj Sadar' AS name, 'BD-UNION-2615' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Bausha' AS name, 'BD-UNION-2616' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Debparra' AS name, 'BD-UNION-2617' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Gaznaipur' AS name, 'BD-UNION-2618' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Kaliarbhanga' AS name, 'BD-UNION-2619' AS code
  UNION ALL
    SELECT 'BD-UPZ-292' AS parent_code, 'union' AS area_type, 'Paniumda' AS name, 'BD-UNION-2620' AS code
  UNION ALL
    SELECT 'BD-UPZ-293' AS parent_code, 'union' AS area_type, 'Snanghat' AS name, 'BD-UNION-2621' AS code
  UNION ALL
    SELECT 'BD-UPZ-293' AS parent_code, 'union' AS area_type, 'Putijuri' AS name, 'BD-UNION-2622' AS code
  UNION ALL
    SELECT 'BD-UPZ-293' AS parent_code, 'union' AS area_type, 'Satkapon' AS name, 'BD-UNION-2623' AS code
  UNION ALL
    SELECT 'BD-UPZ-293' AS parent_code, 'union' AS area_type, 'Bahubal Sadar' AS name, 'BD-UNION-2624' AS code
  UNION ALL
    SELECT 'BD-UPZ-293' AS parent_code, 'union' AS area_type, 'Lamatashi' AS name, 'BD-UNION-2625' AS code
  UNION ALL
    SELECT 'BD-UPZ-293' AS parent_code, 'union' AS area_type, 'Mirpur' AS name, 'BD-UNION-2626' AS code
  UNION ALL
    SELECT 'BD-UPZ-293' AS parent_code, 'union' AS area_type, 'Bhadeshwar' AS name, 'BD-UNION-2627' AS code
  UNION ALL
    SELECT 'BD-UPZ-294' AS parent_code, 'union' AS area_type, 'Shibpasha' AS name, 'BD-UNION-2628' AS code
  UNION ALL
    SELECT 'BD-UPZ-294' AS parent_code, 'union' AS area_type, 'Kakailsao' AS name, 'BD-UNION-2629' AS code
  UNION ALL
    SELECT 'BD-UPZ-294' AS parent_code, 'union' AS area_type, 'Ajmiriganj Sadar' AS name, 'BD-UNION-2630' AS code
  UNION ALL
    SELECT 'BD-UPZ-294' AS parent_code, 'union' AS area_type, 'Badolpur' AS name, 'BD-UNION-2631' AS code
  UNION ALL
    SELECT 'BD-UPZ-294' AS parent_code, 'union' AS area_type, 'Jolsuka' AS name, 'BD-UNION-2632' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Baniachong North East' AS name, 'BD-UNION-2633' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Baniachong North West' AS name, 'BD-UNION-2634' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Baniachong South East' AS name, 'BD-UNION-2635' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Baniachong South West' AS name, 'BD-UNION-2636' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Daulatpur' AS name, 'BD-UNION-2637' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Khagaura' AS name, 'BD-UNION-2638' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Baraiuri' AS name, 'BD-UNION-2639' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Kagapasha' AS name, 'BD-UNION-2640' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Pukra' AS name, 'BD-UNION-2641' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Subidpur' AS name, 'BD-UNION-2642' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Makrampur' AS name, 'BD-UNION-2643' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Sujatpur' AS name, 'BD-UNION-2644' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Mandari' AS name, 'BD-UNION-2645' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Muradpur' AS name, 'BD-UNION-2646' AS code
  UNION ALL
    SELECT 'BD-UPZ-295' AS parent_code, 'union' AS area_type, 'Pailarkandi' AS name, 'BD-UNION-2647' AS code
  UNION ALL
    SELECT 'BD-UPZ-296' AS parent_code, 'union' AS area_type, 'Lakhai' AS name, 'BD-UNION-2648' AS code
  UNION ALL
    SELECT 'BD-UPZ-296' AS parent_code, 'union' AS area_type, 'Murakari' AS name, 'BD-UNION-2649' AS code
  UNION ALL
    SELECT 'BD-UPZ-296' AS parent_code, 'union' AS area_type, 'Muriauk' AS name, 'BD-UNION-2650' AS code
  UNION ALL
    SELECT 'BD-UPZ-296' AS parent_code, 'union' AS area_type, 'Bamoi' AS name, 'BD-UNION-2651' AS code
  UNION ALL
    SELECT 'BD-UPZ-296' AS parent_code, 'union' AS area_type, 'Karab' AS name, 'BD-UNION-2652' AS code
  UNION ALL
    SELECT 'BD-UPZ-296' AS parent_code, 'union' AS area_type, 'Bulla' AS name, 'BD-UNION-2653' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Gazipur' AS name, 'BD-UNION-2654' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Ahammadabad' AS name, 'BD-UNION-2655' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Deorgach' AS name, 'BD-UNION-2656' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Paikpara' AS name, 'BD-UNION-2657' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Shankhala' AS name, 'BD-UNION-2658' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Chunarughat' AS name, 'BD-UNION-2659' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Ubahata' AS name, 'BD-UNION-2660' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Shatiajuri' AS name, 'BD-UNION-2661' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Ranigaon' AS name, 'BD-UNION-2662' AS code
  UNION ALL
    SELECT 'BD-UPZ-297' AS parent_code, 'union' AS area_type, 'Mirashi' AS name, 'BD-UNION-2663' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Lukra' AS name, 'BD-UNION-2664' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Richi' AS name, 'BD-UNION-2665' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Teghoria' AS name, 'BD-UNION-2666' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Poil' AS name, 'BD-UNION-2667' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Gopaya' AS name, 'BD-UNION-2668' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Rajiura' AS name, 'BD-UNION-2669' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Nurpur' AS name, 'BD-UNION-2670' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Shayestaganj' AS name, 'BD-UNION-2671' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Nijampur' AS name, 'BD-UNION-2672' AS code
  UNION ALL
    SELECT 'BD-UPZ-298' AS parent_code, 'union' AS area_type, 'Laskerpur' AS name, 'BD-UNION-2673' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Dharmaghar' AS name, 'BD-UNION-2674' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Choumohani' AS name, 'BD-UNION-2675' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Bahara' AS name, 'BD-UNION-2676' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Adaoir' AS name, 'BD-UNION-2677' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Andiura' AS name, 'BD-UNION-2678' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Shahjahanpur' AS name, 'BD-UNION-2679' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Jagadishpur' AS name, 'BD-UNION-2680' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Bulla' AS name, 'BD-UNION-2681' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Noapara' AS name, 'BD-UNION-2682' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Chhatiain' AS name, 'BD-UNION-2683' AS code
  UNION ALL
    SELECT 'BD-UPZ-299' AS parent_code, 'union' AS area_type, 'Bagashura' AS name, 'BD-UNION-2684' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Jahangirnagar' AS name, 'BD-UNION-2685' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Rangarchar' AS name, 'BD-UNION-2686' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Aptabnagar' AS name, 'BD-UNION-2687' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Gourarang' AS name, 'BD-UNION-2688' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Mollapara' AS name, 'BD-UNION-2689' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Laxmansree' AS name, 'BD-UNION-2690' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Kathair' AS name, 'BD-UNION-2691' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Surma' AS name, 'BD-UNION-2692' AS code
  UNION ALL
    SELECT 'BD-UPZ-300' AS parent_code, 'union' AS area_type, 'Mohonpur' AS name, 'BD-UNION-2693' AS code
  UNION ALL
    SELECT 'BD-UPZ-301' AS parent_code, 'union' AS area_type, 'Shimulbak' AS name, 'BD-UNION-2694' AS code
  UNION ALL
    SELECT 'BD-UPZ-301' AS parent_code, 'union' AS area_type, 'Paschim Pagla' AS name, 'BD-UNION-2695' AS code
  UNION ALL
    SELECT 'BD-UPZ-301' AS parent_code, 'union' AS area_type, 'Joykalash' AS name, 'BD-UNION-2696' AS code
  UNION ALL
    SELECT 'BD-UPZ-301' AS parent_code, 'union' AS area_type, 'Purba Pagla' AS name, 'BD-UNION-2697' AS code
  UNION ALL
    SELECT 'BD-UPZ-301' AS parent_code, 'union' AS area_type, 'Patharia' AS name, 'BD-UNION-2698' AS code
  UNION ALL
    SELECT 'BD-UPZ-301' AS parent_code, 'union' AS area_type, 'Purba Birgaon' AS name, 'BD-UNION-2699' AS code
  UNION ALL
    SELECT 'BD-UPZ-301' AS parent_code, 'union' AS area_type, 'Dargapasha' AS name, 'BD-UNION-2700' AS code
  UNION ALL
    SELECT 'BD-UPZ-301' AS parent_code, 'union' AS area_type, 'Paschim Birgaon' AS name, 'BD-UNION-2701' AS code
  UNION ALL
    SELECT 'BD-UPZ-302' AS parent_code, 'union' AS area_type, 'Palash' AS name, 'BD-UNION-2702' AS code
  UNION ALL
    SELECT 'BD-UPZ-302' AS parent_code, 'union' AS area_type, 'Solukabad' AS name, 'BD-UNION-2703' AS code
  UNION ALL
    SELECT 'BD-UPZ-302' AS parent_code, 'union' AS area_type, 'Dhanpur' AS name, 'BD-UNION-2704' AS code
  UNION ALL
    SELECT 'BD-UPZ-302' AS parent_code, 'union' AS area_type, 'Badaghat South' AS name, 'BD-UNION-2705' AS code
  UNION ALL
    SELECT 'BD-UPZ-302' AS parent_code, 'union' AS area_type, 'Fatepur' AS name, 'BD-UNION-2706' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Islampur' AS name, 'BD-UNION-2707' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Noarai' AS name, 'BD-UNION-2708' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Chhatak Sadar' AS name, 'BD-UNION-2709' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Kalaruka' AS name, 'BD-UNION-2710' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Gobindganj-Syedergaon' AS name, 'BD-UNION-2711' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Chhaila Afjalabad' AS name, 'BD-UNION-2712' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Khurma North' AS name, 'BD-UNION-2713' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Khurma South' AS name, 'BD-UNION-2714' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Chormohalla' AS name, 'BD-UNION-2715' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Jauwabazar' AS name, 'BD-UNION-2716' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Singchapair' AS name, 'BD-UNION-2717' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Dolarbazar' AS name, 'BD-UNION-2718' AS code
  UNION ALL
    SELECT 'BD-UPZ-303' AS parent_code, 'union' AS area_type, 'Bhatgaon' AS name, 'BD-UNION-2719' AS code
  UNION ALL
    SELECT 'BD-UPZ-304' AS parent_code, 'union' AS area_type, 'Kolkolia' AS name, 'BD-UNION-2720' AS code
  UNION ALL
    SELECT 'BD-UPZ-304' AS parent_code, 'union' AS area_type, 'Patli' AS name, 'BD-UNION-2721' AS code
  UNION ALL
    SELECT 'BD-UPZ-304' AS parent_code, 'union' AS area_type, 'Mirpur' AS name, 'BD-UNION-2722' AS code
  UNION ALL
    SELECT 'BD-UPZ-304' AS parent_code, 'union' AS area_type, 'Chilaura Holdipur' AS name, 'BD-UNION-2723' AS code
  UNION ALL
    SELECT 'BD-UPZ-304' AS parent_code, 'union' AS area_type, 'Raniganj' AS name, 'BD-UNION-2724' AS code
  UNION ALL
    SELECT 'BD-UPZ-304' AS parent_code, 'union' AS area_type, 'Syedpur Shaharpara' AS name, 'BD-UNION-2725' AS code
  UNION ALL
    SELECT 'BD-UPZ-304' AS parent_code, 'union' AS area_type, 'Asharkandi' AS name, 'BD-UNION-2726' AS code
  UNION ALL
    SELECT 'BD-UPZ-304' AS parent_code, 'union' AS area_type, 'Pailgaon' AS name, 'BD-UNION-2727' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Banglabazar' AS name, 'BD-UNION-2728' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Norsingpur' AS name, 'BD-UNION-2729' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Dowarabazar' AS name, 'BD-UNION-2730' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Mannargaon' AS name, 'BD-UNION-2731' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Pandargaon' AS name, 'BD-UNION-2732' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Dohalia' AS name, 'BD-UNION-2733' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Laxmipur' AS name, 'BD-UNION-2734' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Boglabazar' AS name, 'BD-UNION-2735' AS code
  UNION ALL
    SELECT 'BD-UPZ-305' AS parent_code, 'union' AS area_type, 'Surma' AS name, 'BD-UNION-2736' AS code
  UNION ALL
    SELECT 'BD-UPZ-306' AS parent_code, 'union' AS area_type, 'Sreepur North' AS name, 'BD-UNION-2737' AS code
  UNION ALL
    SELECT 'BD-UPZ-306' AS parent_code, 'union' AS area_type, 'Sreepur South' AS name, 'BD-UNION-2738' AS code
  UNION ALL
    SELECT 'BD-UPZ-306' AS parent_code, 'union' AS area_type, 'Bordal South' AS name, 'BD-UNION-2739' AS code
  UNION ALL
    SELECT 'BD-UPZ-306' AS parent_code, 'union' AS area_type, 'Bordal North' AS name, 'BD-UNION-2740' AS code
  UNION ALL
    SELECT 'BD-UPZ-306' AS parent_code, 'union' AS area_type, 'Badaghat' AS name, 'BD-UNION-2741' AS code
  UNION ALL
    SELECT 'BD-UPZ-306' AS parent_code, 'union' AS area_type, 'Tahirpur Sadar' AS name, 'BD-UNION-2742' AS code
  UNION ALL
    SELECT 'BD-UPZ-306' AS parent_code, 'union' AS area_type, 'Balijuri' AS name, 'BD-UNION-2743' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Bongshikunda North' AS name, 'BD-UNION-2744' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Bongshikunda South' AS name, 'BD-UNION-2745' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Chamordani' AS name, 'BD-UNION-2746' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Madhyanagar' AS name, 'BD-UNION-2747' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Paikurati' AS name, 'BD-UNION-2748' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Selbarash' AS name, 'BD-UNION-2749' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Dharmapasha Sadar' AS name, 'BD-UNION-2750' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Joyasree' AS name, 'BD-UNION-2751' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Sukhair Rajapur North' AS name, 'BD-UNION-2752' AS code
  UNION ALL
    SELECT 'BD-UPZ-307' AS parent_code, 'union' AS area_type, 'Sukhair Rajapur South' AS name, 'BD-UNION-2753' AS code
  UNION ALL
    SELECT 'BD-UPZ-308' AS parent_code, 'union' AS area_type, 'Beheli' AS name, 'BD-UNION-2754' AS code
  UNION ALL
    SELECT 'BD-UPZ-308' AS parent_code, 'union' AS area_type, 'Sachnabazar' AS name, 'BD-UNION-2755' AS code
  UNION ALL
    SELECT 'BD-UPZ-308' AS parent_code, 'union' AS area_type, 'Bhimkhali' AS name, 'BD-UNION-2756' AS code
  UNION ALL
    SELECT 'BD-UPZ-308' AS parent_code, 'union' AS area_type, 'Fenerbak' AS name, 'BD-UNION-2757' AS code
  UNION ALL
    SELECT 'BD-UPZ-308' AS parent_code, 'union' AS area_type, 'Jamalganj Sadar' AS name, 'BD-UNION-2758' AS code
  UNION ALL
    SELECT 'BD-UPZ-309' AS parent_code, 'union' AS area_type, 'Atgaon' AS name, 'BD-UNION-2759' AS code
  UNION ALL
    SELECT 'BD-UPZ-309' AS parent_code, 'union' AS area_type, 'Habibpur' AS name, 'BD-UNION-2760' AS code
  UNION ALL
    SELECT 'BD-UPZ-309' AS parent_code, 'union' AS area_type, 'Bahara' AS name, 'BD-UNION-2761' AS code
  UNION ALL
    SELECT 'BD-UPZ-309' AS parent_code, 'union' AS area_type, 'Shalla Sadar' AS name, 'BD-UNION-2762' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Rafinagar' AS name, 'BD-UNION-2763' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Bhatipara' AS name, 'BD-UNION-2764' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Rajanagar' AS name, 'BD-UNION-2765' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Charnarchar' AS name, 'BD-UNION-2766' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Derai Sarmangal' AS name, 'BD-UNION-2767' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Karimpur' AS name, 'BD-UNION-2768' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Jagddol' AS name, 'BD-UNION-2769' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Taral' AS name, 'BD-UNION-2770' AS code
  UNION ALL
    SELECT 'BD-UPZ-310' AS parent_code, 'union' AS area_type, 'Kulanj' AS name, 'BD-UNION-2771' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Amlaba' AS name, 'BD-UNION-2772' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Bajnaba' AS name, 'BD-UNION-2773' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Belabo' AS name, 'BD-UNION-2774' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Binnabayd' AS name, 'BD-UNION-2775' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Charuzilab' AS name, 'BD-UNION-2776' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Naraynpur' AS name, 'BD-UNION-2777' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Sallabad' AS name, 'BD-UNION-2778' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Patuli' AS name, 'BD-UNION-2779' AS code
  UNION ALL
    SELECT 'BD-UPZ-311' AS parent_code, 'union' AS area_type, 'Diara' AS name, 'BD-UNION-2780' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Barachapa' AS name, 'BD-UNION-2781' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Chalakchar' AS name, 'BD-UNION-2782' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Charmandalia' AS name, 'BD-UNION-2783' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Ekduaria' AS name, 'BD-UNION-2784' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Gotashia' AS name, 'BD-UNION-2785' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Kanchikata' AS name, 'BD-UNION-2786' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Khidirpur' AS name, 'BD-UNION-2787' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Shukundi' AS name, 'BD-UNION-2788' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Dawlatpur' AS name, 'BD-UNION-2789' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Krisnopur' AS name, 'BD-UNION-2790' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Labutala' AS name, 'BD-UNION-2791' AS code
  UNION ALL
    SELECT 'BD-UPZ-312' AS parent_code, 'union' AS area_type, 'Chandanbari' AS name, 'BD-UNION-2792' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Alokbali' AS name, 'BD-UNION-2793' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Chardighaldi' AS name, 'BD-UNION-2794' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Chinishpur' AS name, 'BD-UNION-2795' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Hajipur' AS name, 'BD-UNION-2796' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Karimpur' AS name, 'BD-UNION-2797' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Khathalia' AS name, 'BD-UNION-2798' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Nuralapur' AS name, 'BD-UNION-2799' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Mahishasura' AS name, 'BD-UNION-2800' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;