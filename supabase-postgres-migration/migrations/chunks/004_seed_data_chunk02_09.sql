INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Meherpara' AS name, 'BD-UNION-2801' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Nazarpur' AS name, 'BD-UNION-2802' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Paikarchar' AS name, 'BD-UNION-2803' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Panchdona' AS name, 'BD-UNION-2804' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Silmandi' AS name, 'BD-UNION-2805' AS code
  UNION ALL
    SELECT 'BD-UPZ-313' AS parent_code, 'union' AS area_type, 'Amdia' AS name, 'BD-UNION-2806' AS code
  UNION ALL
    SELECT 'BD-UPZ-314' AS parent_code, 'union' AS area_type, 'Danga' AS name, 'BD-UNION-2807' AS code
  UNION ALL
    SELECT 'BD-UPZ-314' AS parent_code, 'union' AS area_type, 'Charsindur' AS name, 'BD-UNION-2808' AS code
  UNION ALL
    SELECT 'BD-UPZ-314' AS parent_code, 'union' AS area_type, 'Jinardi' AS name, 'BD-UNION-2809' AS code
  UNION ALL
    SELECT 'BD-UPZ-314' AS parent_code, 'union' AS area_type, 'Gazaria' AS name, 'BD-UNION-2810' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Chanpur' AS name, 'BD-UNION-2811' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Alipura' AS name, 'BD-UNION-2812' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Amirganj' AS name, 'BD-UNION-2813' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Adiabad' AS name, 'BD-UNION-2814' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Banshgari' AS name, 'BD-UNION-2815' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Chanderkandi' AS name, 'BD-UNION-2816' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Chararalia' AS name, 'BD-UNION-2817' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Charmadhua' AS name, 'BD-UNION-2818' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Charsubuddi' AS name, 'BD-UNION-2819' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Daukarchar' AS name, 'BD-UNION-2820' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Hairmara' AS name, 'BD-UNION-2821' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Maheshpur' AS name, 'BD-UNION-2822' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Mirzanagar' AS name, 'BD-UNION-2823' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Mirzarchar' AS name, 'BD-UNION-2824' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Nilakhya' AS name, 'BD-UNION-2825' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Palashtali' AS name, 'BD-UNION-2826' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Paratali' AS name, 'BD-UNION-2827' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Sreenagar' AS name, 'BD-UNION-2828' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Roypura' AS name, 'BD-UNION-2829' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Musapur' AS name, 'BD-UNION-2830' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Uttar Bakharnagar' AS name, 'BD-UNION-2831' AS code
  UNION ALL
    SELECT 'BD-UPZ-315' AS parent_code, 'union' AS area_type, 'Marjal' AS name, 'BD-UNION-2832' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Dulalpur' AS name, 'BD-UNION-2833' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Joynagar' AS name, 'BD-UNION-2834' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Sadharchar' AS name, 'BD-UNION-2835' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Masimpur' AS name, 'BD-UNION-2836' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Chakradha' AS name, 'BD-UNION-2837' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Joshar' AS name, 'BD-UNION-2838' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Baghabo' AS name, 'BD-UNION-2839' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Ayubpur' AS name, 'BD-UNION-2840' AS code
  UNION ALL
    SELECT 'BD-UPZ-316' AS parent_code, 'union' AS area_type, 'Putia' AS name, 'BD-UNION-2841' AS code
  UNION ALL
    SELECT 'BD-UPZ-317' AS parent_code, 'union' AS area_type, 'Bahadursadi' AS name, 'BD-UNION-2842' AS code
  UNION ALL
    SELECT 'BD-UPZ-317' AS parent_code, 'union' AS area_type, 'Baktarpur' AS name, 'BD-UNION-2843' AS code
  UNION ALL
    SELECT 'BD-UPZ-317' AS parent_code, 'union' AS area_type, 'Jamalpurnew' AS name, 'BD-UNION-2844' AS code
  UNION ALL
    SELECT 'BD-UPZ-317' AS parent_code, 'union' AS area_type, 'Jangalia' AS name, 'BD-UNION-2845' AS code
  UNION ALL
    SELECT 'BD-UPZ-317' AS parent_code, 'union' AS area_type, 'Moktarpur' AS name, 'BD-UNION-2846' AS code
  UNION ALL
    SELECT 'BD-UPZ-317' AS parent_code, 'union' AS area_type, 'Nagari' AS name, 'BD-UNION-2847' AS code
  UNION ALL
    SELECT 'BD-UPZ-317' AS parent_code, 'union' AS area_type, 'Tumulia' AS name, 'BD-UNION-2848' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Atabaha' AS name, 'BD-UNION-2849' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Boali' AS name, 'BD-UNION-2850' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Chapair' AS name, 'BD-UNION-2851' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Dhaliora' AS name, 'BD-UNION-2852' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Fulbaria' AS name, 'BD-UNION-2853' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Madhyapara' AS name, 'BD-UNION-2854' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Mouchak' AS name, 'BD-UNION-2855' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Sutrapur' AS name, 'BD-UNION-2856' AS code
  UNION ALL
    SELECT 'BD-UPZ-318' AS parent_code, 'union' AS area_type, 'Srifaltali' AS name, 'BD-UNION-2857' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Barishaba' AS name, 'BD-UNION-2858' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Ghagotia' AS name, 'BD-UNION-2859' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Kapasia' AS name, 'BD-UNION-2860' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Chandpur' AS name, 'BD-UNION-2861' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Targoan' AS name, 'BD-UNION-2862' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Karihata' AS name, 'BD-UNION-2863' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Tokh' AS name, 'BD-UNION-2864' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Sinhasree' AS name, 'BD-UNION-2865' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-2866' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Sonmania' AS name, 'BD-UNION-2867' AS code
  UNION ALL
    SELECT 'BD-UPZ-319' AS parent_code, 'union' AS area_type, 'Rayed' AS name, 'BD-UNION-2868' AS code
  UNION ALL
    SELECT 'BD-UPZ-320' AS parent_code, 'union' AS area_type, 'Baria' AS name, 'BD-UNION-2869' AS code
  UNION ALL
    SELECT 'BD-UPZ-320' AS parent_code, 'union' AS area_type, 'Basan' AS name, 'BD-UNION-2870' AS code
  UNION ALL
    SELECT 'BD-UPZ-320' AS parent_code, 'union' AS area_type, 'Gachha' AS name, 'BD-UNION-2871' AS code
  UNION ALL
    SELECT 'BD-UPZ-320' AS parent_code, 'union' AS area_type, 'Kashimpur' AS name, 'BD-UNION-2872' AS code
  UNION ALL
    SELECT 'BD-UPZ-320' AS parent_code, 'union' AS area_type, 'Kayaltia' AS name, 'BD-UNION-2873' AS code
  UNION ALL
    SELECT 'BD-UPZ-320' AS parent_code, 'union' AS area_type, 'Konabari' AS name, 'BD-UNION-2874' AS code
  UNION ALL
    SELECT 'BD-UPZ-320' AS parent_code, 'union' AS area_type, 'Mirzapur' AS name, 'BD-UNION-2875' AS code
  UNION ALL
    SELECT 'BD-UPZ-320' AS parent_code, 'union' AS area_type, 'Pubail' AS name, 'BD-UNION-2876' AS code
  UNION ALL
    SELECT 'BD-UPZ-321' AS parent_code, 'union' AS area_type, 'Barmi' AS name, 'BD-UNION-2877' AS code
  UNION ALL
    SELECT 'BD-UPZ-321' AS parent_code, 'union' AS area_type, 'Gazipur' AS name, 'BD-UNION-2878' AS code
  UNION ALL
    SELECT 'BD-UPZ-321' AS parent_code, 'union' AS area_type, 'Gosinga' AS name, 'BD-UNION-2879' AS code
  UNION ALL
    SELECT 'BD-UPZ-321' AS parent_code, 'union' AS area_type, 'Maona' AS name, 'BD-UNION-2880' AS code
  UNION ALL
    SELECT 'BD-UPZ-321' AS parent_code, 'union' AS area_type, 'Kaoraid' AS name, 'BD-UNION-2881' AS code
  UNION ALL
    SELECT 'BD-UPZ-321' AS parent_code, 'union' AS area_type, 'Prahladpur' AS name, 'BD-UNION-2882' AS code
  UNION ALL
    SELECT 'BD-UPZ-321' AS parent_code, 'union' AS area_type, 'Rajabari' AS name, 'BD-UNION-2883' AS code
  UNION ALL
    SELECT 'BD-UPZ-321' AS parent_code, 'union' AS area_type, 'Telihati' AS name, 'BD-UNION-2884' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Binodpur' AS name, 'BD-UNION-2885' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Tulasar' AS name, 'BD-UNION-2886' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Palong' AS name, 'BD-UNION-2887' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Domshar' AS name, 'BD-UNION-2888' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Rudrakar' AS name, 'BD-UNION-2889' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Angaria' AS name, 'BD-UNION-2890' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Chitolia' AS name, 'BD-UNION-2891' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Mahmudpur' AS name, 'BD-UNION-2892' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Chikondi' AS name, 'BD-UNION-2893' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Chandrapur' AS name, 'BD-UNION-2894' AS code
  UNION ALL
    SELECT 'BD-UPZ-322' AS parent_code, 'union' AS area_type, 'Shulpara' AS name, 'BD-UNION-2895' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Kedarpur' AS name, 'BD-UNION-2896' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Dingamanik' AS name, 'BD-UNION-2897' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Garishar' AS name, 'BD-UNION-2898' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Nowpara' AS name, 'BD-UNION-2899' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Moktererchar' AS name, 'BD-UNION-2900' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Charatra' AS name, 'BD-UNION-2901' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Rajnagar' AS name, 'BD-UNION-2902' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Japsa' AS name, 'BD-UNION-2903' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Vojeshwar' AS name, 'BD-UNION-2904' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Fategongpur' AS name, 'BD-UNION-2905' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Bijari' AS name, 'BD-UNION-2906' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Vumkhara' AS name, 'BD-UNION-2907' AS code
  UNION ALL
    SELECT 'BD-UPZ-323' AS parent_code, 'union' AS area_type, 'Nashason' AS name, 'BD-UNION-2908' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Zajira Sadar' AS name, 'BD-UNION-2909' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Mulna' AS name, 'BD-UNION-2910' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Barokandi' AS name, 'BD-UNION-2911' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Bilaspur' AS name, 'BD-UNION-2912' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Kundarchar' AS name, 'BD-UNION-2913' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Palerchar' AS name, 'BD-UNION-2914' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Purba Nawdoba' AS name, 'BD-UNION-2915' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Nawdoba' AS name, 'BD-UNION-2916' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Shenerchar' AS name, 'BD-UNION-2917' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Bknagar' AS name, 'BD-UNION-2918' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Barogopalpur' AS name, 'BD-UNION-2919' AS code
  UNION ALL
    SELECT 'BD-UPZ-324' AS parent_code, 'union' AS area_type, 'Jaynagor' AS name, 'BD-UNION-2920' AS code
  UNION ALL
    SELECT 'BD-UPZ-325' AS parent_code, 'union' AS area_type, 'Nager Para' AS name, 'BD-UNION-2921' AS code
  UNION ALL
    SELECT 'BD-UPZ-325' AS parent_code, 'union' AS area_type, 'Alaolpur' AS name, 'BD-UNION-2922' AS code
  UNION ALL
    SELECT 'BD-UPZ-325' AS parent_code, 'union' AS area_type, 'Kodalpur' AS name, 'BD-UNION-2923' AS code
  UNION ALL
    SELECT 'BD-UPZ-325' AS parent_code, 'union' AS area_type, 'Goshairhat' AS name, 'BD-UNION-2924' AS code
  UNION ALL
    SELECT 'BD-UPZ-325' AS parent_code, 'union' AS area_type, 'Edilpur' AS name, 'BD-UNION-2925' AS code
  UNION ALL
    SELECT 'BD-UPZ-325' AS parent_code, 'union' AS area_type, 'Nalmuri' AS name, 'BD-UNION-2926' AS code
  UNION ALL
    SELECT 'BD-UPZ-325' AS parent_code, 'union' AS area_type, 'Samontasar' AS name, 'BD-UNION-2927' AS code
  UNION ALL
    SELECT 'BD-UPZ-325' AS parent_code, 'union' AS area_type, 'Kuchipatti' AS name, 'BD-UNION-2928' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Ramvadrapur' AS name, 'BD-UNION-2929' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Mahisar' AS name, 'BD-UNION-2930' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Saygaon' AS name, 'BD-UNION-2931' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Narayanpur' AS name, 'BD-UNION-2932' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'D.M Khali' AS name, 'BD-UNION-2933' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Charkumaria' AS name, 'BD-UNION-2934' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Sakhipur' AS name, 'BD-UNION-2935' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Kachikata' AS name, 'BD-UNION-2936' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'North Tarabunia' AS name, 'BD-UNION-2937' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Charvaga' AS name, 'BD-UNION-2938' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Arsinagar' AS name, 'BD-UNION-2939' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'South Tarabunia' AS name, 'BD-UNION-2940' AS code
  UNION ALL
    SELECT 'BD-UPZ-326' AS parent_code, 'union' AS area_type, 'Charsensas' AS name, 'BD-UNION-2941' AS code
  UNION ALL
    SELECT 'BD-UPZ-327' AS parent_code, 'union' AS area_type, 'Shidulkura' AS name, 'BD-UNION-2942' AS code
  UNION ALL
    SELECT 'BD-UPZ-327' AS parent_code, 'union' AS area_type, 'Kaneshar' AS name, 'BD-UNION-2943' AS code
  UNION ALL
    SELECT 'BD-UPZ-327' AS parent_code, 'union' AS area_type, 'Purba Damudya' AS name, 'BD-UNION-2944' AS code
  UNION ALL
    SELECT 'BD-UPZ-327' AS parent_code, 'union' AS area_type, 'Islampur' AS name, 'BD-UNION-2945' AS code
  UNION ALL
    SELECT 'BD-UPZ-327' AS parent_code, 'union' AS area_type, 'Dankati' AS name, 'BD-UNION-2946' AS code
  UNION ALL
    SELECT 'BD-UPZ-327' AS parent_code, 'union' AS area_type, 'Sidya' AS name, 'BD-UNION-2947' AS code
  UNION ALL
    SELECT 'BD-UPZ-327' AS parent_code, 'union' AS area_type, 'Darulaman' AS name, 'BD-UNION-2948' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Satgram' AS name, 'BD-UNION-2949' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Duptara' AS name, 'BD-UNION-2950' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Brahammandi' AS name, 'BD-UNION-2951' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Fatepur' AS name, 'BD-UNION-2952' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Bishnandi' AS name, 'BD-UNION-2953' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Mahmudpur' AS name, 'BD-UNION-2954' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Highjadi' AS name, 'BD-UNION-2955' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Uchitpura' AS name, 'BD-UNION-2956' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Kalapaharia' AS name, 'BD-UNION-2957' AS code
  UNION ALL
    SELECT 'BD-UPZ-328' AS parent_code, 'union' AS area_type, 'Kagkanda' AS name, 'BD-UNION-2958' AS code
  UNION ALL
    SELECT 'BD-UPZ-329' AS parent_code, 'union' AS area_type, 'Musapur' AS name, 'BD-UNION-2959' AS code
  UNION ALL
    SELECT 'BD-UPZ-329' AS parent_code, 'union' AS area_type, 'Modonpur' AS name, 'BD-UNION-2960' AS code
  UNION ALL
    SELECT 'BD-UPZ-329' AS parent_code, 'union' AS area_type, 'Bandar' AS name, 'BD-UNION-2961' AS code
  UNION ALL
    SELECT 'BD-UPZ-329' AS parent_code, 'union' AS area_type, 'Dhamgar' AS name, 'BD-UNION-2962' AS code
  UNION ALL
    SELECT 'BD-UPZ-329' AS parent_code, 'union' AS area_type, 'Kolagathia' AS name, 'BD-UNION-2963' AS code
  UNION ALL
    SELECT 'BD-UPZ-330' AS parent_code, 'union' AS area_type, 'Alirtek' AS name, 'BD-UNION-2964' AS code
  UNION ALL
    SELECT 'BD-UPZ-330' AS parent_code, 'union' AS area_type, 'Kashipur' AS name, 'BD-UNION-2965' AS code
  UNION ALL
    SELECT 'BD-UPZ-330' AS parent_code, 'union' AS area_type, 'Kutubpur' AS name, 'BD-UNION-2966' AS code
  UNION ALL
    SELECT 'BD-UPZ-330' AS parent_code, 'union' AS area_type, 'Gognagar' AS name, 'BD-UNION-2967' AS code
  UNION ALL
    SELECT 'BD-UPZ-330' AS parent_code, 'union' AS area_type, 'Baktaboli' AS name, 'BD-UNION-2968' AS code
  UNION ALL
    SELECT 'BD-UPZ-330' AS parent_code, 'union' AS area_type, 'Enayetnagor' AS name, 'BD-UNION-2969' AS code
  UNION ALL
    SELECT 'BD-UPZ-331' AS parent_code, 'union' AS area_type, 'Murapara' AS name, 'BD-UNION-2970' AS code
  UNION ALL
    SELECT 'BD-UPZ-331' AS parent_code, 'union' AS area_type, 'Bhulta' AS name, 'BD-UNION-2971' AS code
  UNION ALL
    SELECT 'BD-UPZ-331' AS parent_code, 'union' AS area_type, 'Golakandail' AS name, 'BD-UNION-2972' AS code
  UNION ALL
    SELECT 'BD-UPZ-331' AS parent_code, 'union' AS area_type, 'Daudpur' AS name, 'BD-UNION-2973' AS code
  UNION ALL
    SELECT 'BD-UPZ-331' AS parent_code, 'union' AS area_type, 'Rupganj' AS name, 'BD-UNION-2974' AS code
  UNION ALL
    SELECT 'BD-UPZ-331' AS parent_code, 'union' AS area_type, 'Kayetpara' AS name, 'BD-UNION-2975' AS code
  UNION ALL
    SELECT 'BD-UPZ-331' AS parent_code, 'union' AS area_type, 'Bholobo' AS name, 'BD-UNION-2976' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Pirojpur' AS name, 'BD-UNION-2977' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Shambhupura' AS name, 'BD-UNION-2978' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Mograpara' AS name, 'BD-UNION-2979' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Baidyerbazar' AS name, 'BD-UNION-2980' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Baradi' AS name, 'BD-UNION-2981' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Noagaon' AS name, 'BD-UNION-2982' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Jampur' AS name, 'BD-UNION-2983' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Sadipur' AS name, 'BD-UNION-2984' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Sonmandi' AS name, 'BD-UNION-2985' AS code
  UNION ALL
    SELECT 'BD-UPZ-332' AS parent_code, 'union' AS area_type, 'Kanchpur' AS name, 'BD-UNION-2986' AS code
  UNION ALL
    SELECT 'BD-UPZ-333' AS parent_code, 'union' AS area_type, 'Basail' AS name, 'BD-UNION-2987' AS code
  UNION ALL
    SELECT 'BD-UPZ-333' AS parent_code, 'union' AS area_type, 'Kanchanpur' AS name, 'BD-UNION-2988' AS code
  UNION ALL
    SELECT 'BD-UPZ-333' AS parent_code, 'union' AS area_type, 'Habla' AS name, 'BD-UNION-2989' AS code
  UNION ALL
    SELECT 'BD-UPZ-333' AS parent_code, 'union' AS area_type, 'Kashil' AS name, 'BD-UNION-2990' AS code
  UNION ALL
    SELECT 'BD-UPZ-333' AS parent_code, 'union' AS area_type, 'Fulki' AS name, 'BD-UNION-2991' AS code
  UNION ALL
    SELECT 'BD-UPZ-333' AS parent_code, 'union' AS area_type, 'Kauljani' AS name, 'BD-UNION-2992' AS code
  UNION ALL
    SELECT 'BD-UPZ-334' AS parent_code, 'union' AS area_type, 'Arjuna' AS name, 'BD-UNION-2993' AS code
  UNION ALL
    SELECT 'BD-UPZ-334' AS parent_code, 'union' AS area_type, 'Gabshara' AS name, 'BD-UNION-2994' AS code
  UNION ALL
    SELECT 'BD-UPZ-334' AS parent_code, 'union' AS area_type, 'Falda' AS name, 'BD-UNION-2995' AS code
  UNION ALL
    SELECT 'BD-UPZ-334' AS parent_code, 'union' AS area_type, 'Gobindashi' AS name, 'BD-UNION-2996' AS code
  UNION ALL
    SELECT 'BD-UPZ-334' AS parent_code, 'union' AS area_type, 'Aloa' AS name, 'BD-UNION-2997' AS code
  UNION ALL
    SELECT 'BD-UPZ-334' AS parent_code, 'union' AS area_type, 'Nikrail' AS name, 'BD-UNION-2998' AS code
  UNION ALL
    SELECT 'BD-UPZ-335' AS parent_code, 'union' AS area_type, 'Deuli' AS name, 'BD-UNION-2999' AS code
  UNION ALL
    SELECT 'BD-UPZ-335' AS parent_code, 'union' AS area_type, 'Lauhati' AS name, 'BD-UNION-3000' AS code
  UNION ALL
    SELECT 'BD-UPZ-335' AS parent_code, 'union' AS area_type, 'Patharail' AS name, 'BD-UNION-3001' AS code
  UNION ALL
    SELECT 'BD-UPZ-335' AS parent_code, 'union' AS area_type, 'Delduar' AS name, 'BD-UNION-3002' AS code
  UNION ALL
    SELECT 'BD-UPZ-335' AS parent_code, 'union' AS area_type, 'Fazilhati' AS name, 'BD-UNION-3003' AS code
  UNION ALL
    SELECT 'BD-UPZ-335' AS parent_code, 'union' AS area_type, 'Elasin' AS name, 'BD-UNION-3004' AS code
  UNION ALL
    SELECT 'BD-UPZ-335' AS parent_code, 'union' AS area_type, 'Atia' AS name, 'BD-UNION-3005' AS code
  UNION ALL
    SELECT 'BD-UPZ-335' AS parent_code, 'union' AS area_type, 'Dubail' AS name, 'BD-UNION-3006' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Deulabari' AS name, 'BD-UNION-3007' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Ghatail' AS name, 'BD-UNION-3008' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Jamuria' AS name, 'BD-UNION-3009' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Lokerpara' AS name, 'BD-UNION-3010' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Anehola' AS name, 'BD-UNION-3011' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Dighalkandia' AS name, 'BD-UNION-3012' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Digar' AS name, 'BD-UNION-3013' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Deopara' AS name, 'BD-UNION-3014' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Sandhanpur' AS name, 'BD-UNION-3015' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Rasulpur' AS name, 'BD-UNION-3016' AS code
  UNION ALL
    SELECT 'BD-UPZ-336' AS parent_code, 'union' AS area_type, 'Dhalapara' AS name, 'BD-UNION-3017' AS code
  UNION ALL
    SELECT 'BD-UPZ-337' AS parent_code, 'union' AS area_type, 'Hadera' AS name, 'BD-UNION-3018' AS code
  UNION ALL
    SELECT 'BD-UPZ-337' AS parent_code, 'union' AS area_type, 'Jhawail' AS name, 'BD-UNION-3019' AS code
  UNION ALL
    SELECT 'BD-UPZ-337' AS parent_code, 'union' AS area_type, 'Nagdashimla' AS name, 'BD-UNION-3020' AS code
  UNION ALL
    SELECT 'BD-UPZ-337' AS parent_code, 'union' AS area_type, 'Dhopakandi' AS name, 'BD-UNION-3021' AS code
  UNION ALL
    SELECT 'BD-UPZ-337' AS parent_code, 'union' AS area_type, 'Alamnagor' AS name, 'BD-UNION-3022' AS code
  UNION ALL
    SELECT 'BD-UPZ-337' AS parent_code, 'union' AS area_type, 'Hemnagor' AS name, 'BD-UNION-3023' AS code
  UNION ALL
    SELECT 'BD-UPZ-337' AS parent_code, 'union' AS area_type, 'Mirzapur' AS name, 'BD-UNION-3024' AS code
  UNION ALL
    SELECT 'BD-UPZ-338' AS parent_code, 'union' AS area_type, 'Alokdia' AS name, 'BD-UNION-3025' AS code
  UNION ALL
    SELECT 'BD-UPZ-338' AS parent_code, 'union' AS area_type, 'Aushnara' AS name, 'BD-UNION-3026' AS code
  UNION ALL
    SELECT 'BD-UPZ-338' AS parent_code, 'union' AS area_type, 'Aronkhola' AS name, 'BD-UNION-3027' AS code
  UNION ALL
    SELECT 'BD-UPZ-338' AS parent_code, 'union' AS area_type, 'Sholakuri' AS name, 'BD-UNION-3028' AS code
  UNION ALL
    SELECT 'BD-UPZ-338' AS parent_code, 'union' AS area_type, 'Golabari' AS name, 'BD-UNION-3029' AS code
  UNION ALL
    SELECT 'BD-UPZ-338' AS parent_code, 'union' AS area_type, 'Mirjabari' AS name, 'BD-UNION-3030' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Mahera' AS name, 'BD-UNION-3031' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Jamurki' AS name, 'BD-UNION-3032' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Fatepur' AS name, 'BD-UNION-3033' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Banail' AS name, 'BD-UNION-3034' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Anaitara' AS name, 'BD-UNION-3035' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Warshi' AS name, 'BD-UNION-3036' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Bhatram' AS name, 'BD-UNION-3037' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Bahuria' AS name, 'BD-UNION-3038' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Gorai' AS name, 'BD-UNION-3039' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Ajgana' AS name, 'BD-UNION-3040' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Tarafpur' AS name, 'BD-UNION-3041' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Bastail' AS name, 'BD-UNION-3042' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Baora' AS name, 'BD-UNION-3043' AS code
  UNION ALL
    SELECT 'BD-UPZ-339' AS parent_code, 'union' AS area_type, 'Latifpur' AS name, 'BD-UNION-3044' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Bharra' AS name, 'BD-UNION-3045' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Sahabathpur' AS name, 'BD-UNION-3046' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Goyhata' AS name, 'BD-UNION-3047' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Solimabad' AS name, 'BD-UNION-3048' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Nagorpur' AS name, 'BD-UNION-3049' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Mamudnagor' AS name, 'BD-UNION-3050' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Mokna' AS name, 'BD-UNION-3051' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Pakutia' AS name, 'BD-UNION-3052' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Bekrah Atgram' AS name, 'BD-UNION-3053' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Dhuburia' AS name, 'BD-UNION-3054' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Bhadra' AS name, 'BD-UNION-3055' AS code
  UNION ALL
    SELECT 'BD-UPZ-340' AS parent_code, 'union' AS area_type, 'Doptior' AS name, 'BD-UNION-3056' AS code
  UNION ALL
    SELECT 'BD-UPZ-341' AS parent_code, 'union' AS area_type, 'Kakrajan' AS name, 'BD-UNION-3057' AS code
  UNION ALL
    SELECT 'BD-UPZ-341' AS parent_code, 'union' AS area_type, 'Gajaria' AS name, 'BD-UNION-3058' AS code
  UNION ALL
    SELECT 'BD-UPZ-341' AS parent_code, 'union' AS area_type, 'Jaduppur' AS name, 'BD-UNION-3059' AS code
  UNION ALL
    SELECT 'BD-UPZ-341' AS parent_code, 'union' AS area_type, 'Hatibandha' AS name, 'BD-UNION-3060' AS code
  UNION ALL
    SELECT 'BD-UPZ-341' AS parent_code, 'union' AS area_type, 'Kalia' AS name, 'BD-UNION-3061' AS code
  UNION ALL
    SELECT 'BD-UPZ-341' AS parent_code, 'union' AS area_type, 'Dariapur' AS name, 'BD-UNION-3062' AS code
  UNION ALL
    SELECT 'BD-UPZ-341' AS parent_code, 'union' AS area_type, 'Kalmegha' AS name, 'BD-UNION-3063' AS code
  UNION ALL
    SELECT 'BD-UPZ-341' AS parent_code, 'union' AS area_type, 'Baharatoil' AS name, 'BD-UNION-3064' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Mogra' AS name, 'BD-UNION-3065' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Gala' AS name, 'BD-UNION-3066' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Gharinda' AS name, 'BD-UNION-3067' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Karatia' AS name, 'BD-UNION-3068' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Silimpur' AS name, 'BD-UNION-3069' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Porabari' AS name, 'BD-UNION-3070' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Dyenna' AS name, 'BD-UNION-3071' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Baghil' AS name, 'BD-UNION-3072' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Kakua' AS name, 'BD-UNION-3073' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Hugra' AS name, 'BD-UNION-3074' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Katuli' AS name, 'BD-UNION-3075' AS code
  UNION ALL
    SELECT 'BD-UPZ-342' AS parent_code, 'union' AS area_type, 'Mahamudnagar' AS name, 'BD-UNION-3076' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-3077' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Birbashinda' AS name, 'BD-UNION-3078' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Narandia' AS name, 'BD-UNION-3079' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Shahadebpur' AS name, 'BD-UNION-3080' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Kokdahara' AS name, 'BD-UNION-3081' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Balla' AS name, 'BD-UNION-3082' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Salla' AS name, 'BD-UNION-3083' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Nagbari' AS name, 'BD-UNION-3084' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Bangra' AS name, 'BD-UNION-3085' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Paikora' AS name, 'BD-UNION-3086' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Dashokia' AS name, 'BD-UNION-3087' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Parkhi' AS name, 'BD-UNION-3088' AS code
  UNION ALL
    SELECT 'BD-UPZ-343' AS parent_code, 'union' AS area_type, 'Gohaliabari' AS name, 'BD-UNION-3089' AS code
  UNION ALL
    SELECT 'BD-UPZ-344' AS parent_code, 'union' AS area_type, 'Dhopakhali' AS name, 'BD-UNION-3090' AS code
  UNION ALL
    SELECT 'BD-UPZ-344' AS parent_code, 'union' AS area_type, 'Paiska' AS name, 'BD-UNION-3091' AS code
  UNION ALL
    SELECT 'BD-UPZ-344' AS parent_code, 'union' AS area_type, 'Mushuddi' AS name, 'BD-UNION-3092' AS code
  UNION ALL
    SELECT 'BD-UPZ-344' AS parent_code, 'union' AS area_type, 'Bolibodrow' AS name, 'BD-UNION-3093' AS code
  UNION ALL
    SELECT 'BD-UPZ-344' AS parent_code, 'union' AS area_type, 'Birtara' AS name, 'BD-UNION-3094' AS code
  UNION ALL
    SELECT 'BD-UPZ-344' AS parent_code, 'union' AS area_type, 'Baniajan' AS name, 'BD-UNION-3095' AS code
  UNION ALL
    SELECT 'BD-UPZ-344' AS parent_code, 'union' AS area_type, 'Jadunathpur' AS name, 'BD-UNION-3096' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Chawganga' AS name, 'BD-UNION-3097' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Joysiddi' AS name, 'BD-UNION-3098' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Alonjori' AS name, 'BD-UNION-3099' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Badla' AS name, 'BD-UNION-3100' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Boribari' AS name, 'BD-UNION-3101' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Itna' AS name, 'BD-UNION-3102' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Mriga' AS name, 'BD-UNION-3103' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Dhonpur' AS name, 'BD-UNION-3104' AS code
  UNION ALL
    SELECT 'BD-UPZ-345' AS parent_code, 'union' AS area_type, 'Raytoti' AS name, 'BD-UNION-3105' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Banagram' AS name, 'BD-UNION-3106' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Shahasram Dhuldia' AS name, 'BD-UNION-3107' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Kargaon' AS name, 'BD-UNION-3108' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Chandpur' AS name, 'BD-UNION-3109' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Mumurdia' AS name, 'BD-UNION-3110' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Acmita' AS name, 'BD-UNION-3111' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Mosua' AS name, 'BD-UNION-3112' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Lohajuree' AS name, 'BD-UNION-3113' AS code
  UNION ALL
    SELECT 'BD-UPZ-346' AS parent_code, 'union' AS area_type, 'Jalalpur' AS name, 'BD-UNION-3114' AS code
  UNION ALL
    SELECT 'BD-UPZ-347' AS parent_code, 'union' AS area_type, 'Sadekpur' AS name, 'BD-UNION-3115' AS code
  UNION ALL
    SELECT 'BD-UPZ-347' AS parent_code, 'union' AS area_type, 'Aganagar' AS name, 'BD-UNION-3116' AS code
  UNION ALL
    SELECT 'BD-UPZ-347' AS parent_code, 'union' AS area_type, 'Shimulkandi' AS name, 'BD-UNION-3117' AS code
  UNION ALL
    SELECT 'BD-UPZ-347' AS parent_code, 'union' AS area_type, 'Gajaria' AS name, 'BD-UNION-3118' AS code
  UNION ALL
    SELECT 'BD-UPZ-347' AS parent_code, 'union' AS area_type, 'Kalika Prashad' AS name, 'BD-UNION-3119' AS code
  UNION ALL
    SELECT 'BD-UPZ-347' AS parent_code, 'union' AS area_type, 'Sreenagar' AS name, 'BD-UNION-3120' AS code
  UNION ALL
    SELECT 'BD-UPZ-347' AS parent_code, 'union' AS area_type, 'Shibpur' AS name, 'BD-UNION-3121' AS code
  UNION ALL
    SELECT 'BD-UPZ-348' AS parent_code, 'union' AS area_type, 'Taljanga' AS name, 'BD-UNION-3122' AS code
  UNION ALL
    SELECT 'BD-UPZ-348' AS parent_code, 'union' AS area_type, 'Rauti' AS name, 'BD-UNION-3123' AS code
  UNION ALL
    SELECT 'BD-UPZ-348' AS parent_code, 'union' AS area_type, 'Dhola' AS name, 'BD-UNION-3124' AS code
  UNION ALL
    SELECT 'BD-UPZ-348' AS parent_code, 'union' AS area_type, 'Jawar' AS name, 'BD-UNION-3125' AS code
  UNION ALL
    SELECT 'BD-UPZ-348' AS parent_code, 'union' AS area_type, 'Damiha' AS name, 'BD-UNION-3126' AS code
  UNION ALL
    SELECT 'BD-UPZ-348' AS parent_code, 'union' AS area_type, 'Digdair' AS name, 'BD-UNION-3127' AS code
  UNION ALL
    SELECT 'BD-UPZ-348' AS parent_code, 'union' AS area_type, 'Tarail-Sachail' AS name, 'BD-UNION-3128' AS code
  UNION ALL
    SELECT 'BD-UPZ-349' AS parent_code, 'union' AS area_type, 'Jinari' AS name, 'BD-UNION-3129' AS code
  UNION ALL
    SELECT 'BD-UPZ-349' AS parent_code, 'union' AS area_type, 'Gobindapur' AS name, 'BD-UNION-3130' AS code
  UNION ALL
    SELECT 'BD-UPZ-349' AS parent_code, 'union' AS area_type, 'Sidhla' AS name, 'BD-UNION-3131' AS code
  UNION ALL
    SELECT 'BD-UPZ-349' AS parent_code, 'union' AS area_type, 'Araibaria' AS name, 'BD-UNION-3132' AS code
  UNION ALL
    SELECT 'BD-UPZ-349' AS parent_code, 'union' AS area_type, 'Sahedal' AS name, 'BD-UNION-3133' AS code
  UNION ALL
    SELECT 'BD-UPZ-349' AS parent_code, 'union' AS area_type, 'Pumdi' AS name, 'BD-UNION-3134' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Jangalia' AS name, 'BD-UNION-3135' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Hosendi' AS name, 'BD-UNION-3136' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Narandi' AS name, 'BD-UNION-3137' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Shukhia' AS name, 'BD-UNION-3138' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Patuavabga' AS name, 'BD-UNION-3139' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Chandipasha' AS name, 'BD-UNION-3140' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Charfaradi' AS name, 'BD-UNION-3141' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Burudia' AS name, 'BD-UNION-3142' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Egarasindur' AS name, 'BD-UNION-3143' AS code
  UNION ALL
    SELECT 'BD-UPZ-350' AS parent_code, 'union' AS area_type, 'Pakundia' AS name, 'BD-UNION-3144' AS code
  UNION ALL
    SELECT 'BD-UPZ-351' AS parent_code, 'union' AS area_type, 'Ramdi' AS name, 'BD-UNION-3145' AS code
  UNION ALL
    SELECT 'BD-UPZ-351' AS parent_code, 'union' AS area_type, 'Osmanpur' AS name, 'BD-UNION-3146' AS code
  UNION ALL
    SELECT 'BD-UPZ-351' AS parent_code, 'union' AS area_type, 'Chhaysuti' AS name, 'BD-UNION-3147' AS code
  UNION ALL
    SELECT 'BD-UPZ-351' AS parent_code, 'union' AS area_type, 'Salua' AS name, 'BD-UNION-3148' AS code
  UNION ALL
    SELECT 'BD-UPZ-351' AS parent_code, 'union' AS area_type, 'Gobaria Abdullahpur' AS name, 'BD-UNION-3149' AS code
  UNION ALL
    SELECT 'BD-UPZ-351' AS parent_code, 'union' AS area_type, 'Faridpur' AS name, 'BD-UNION-3150' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Rashidabad' AS name, 'BD-UNION-3151' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Latibabad' AS name, 'BD-UNION-3152' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Maizkhapan' AS name, 'BD-UNION-3153' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Mohinanda' AS name, 'BD-UNION-3154' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Joshodal' AS name, 'BD-UNION-3155' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Bowlai' AS name, 'BD-UNION-3156' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Binnati' AS name, 'BD-UNION-3157' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Maria' AS name, 'BD-UNION-3158' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Chowddoshata' AS name, 'BD-UNION-3159' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Karshakarial' AS name, 'BD-UNION-3160' AS code
  UNION ALL
    SELECT 'BD-UPZ-352' AS parent_code, 'union' AS area_type, 'Danapatuli' AS name, 'BD-UNION-3161' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Kadirjangal' AS name, 'BD-UNION-3162' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Gujadia' AS name, 'BD-UNION-3163' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Kiraton' AS name, 'BD-UNION-3164' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Barogharia' AS name, 'BD-UNION-3165' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Niamatpur' AS name, 'BD-UNION-3166' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Dehunda' AS name, 'BD-UNION-3167' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Sutarpara' AS name, 'BD-UNION-3168' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Gunodhar' AS name, 'BD-UNION-3169' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Joyka' AS name, 'BD-UNION-3170' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Zafrabad' AS name, 'BD-UNION-3171' AS code
  UNION ALL
    SELECT 'BD-UPZ-353' AS parent_code, 'union' AS area_type, 'Noabad' AS name, 'BD-UNION-3172' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Kailag' AS name, 'BD-UNION-3173' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Pirijpur' AS name, 'BD-UNION-3174' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Gazirchar' AS name, 'BD-UNION-3175' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Hilochia' AS name, 'BD-UNION-3176' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Maijchar9' AS name, 'BD-UNION-3177' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Homypur' AS name, 'BD-UNION-3178' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Halimpur' AS name, 'BD-UNION-3179' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Sararchar' AS name, 'BD-UNION-3180' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Dilalpur' AS name, 'BD-UNION-3181' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Dighirpar' AS name, 'BD-UNION-3182' AS code
  UNION ALL
    SELECT 'BD-UPZ-354' AS parent_code, 'union' AS area_type, 'Boliardi' AS name, 'BD-UNION-3183' AS code
  UNION ALL
    SELECT 'BD-UPZ-355' AS parent_code, 'union' AS area_type, 'Dewghar' AS name, 'BD-UNION-3184' AS code
  UNION ALL
    SELECT 'BD-UPZ-355' AS parent_code, 'union' AS area_type, 'Kastul' AS name, 'BD-UNION-3185' AS code
  UNION ALL
    SELECT 'BD-UPZ-355' AS parent_code, 'union' AS area_type, 'Austagram Sadar' AS name, 'BD-UNION-3186' AS code
  UNION ALL
    SELECT 'BD-UPZ-355' AS parent_code, 'union' AS area_type, 'Bangalpara' AS name, 'BD-UNION-3187' AS code
  UNION ALL
    SELECT 'BD-UPZ-355' AS parent_code, 'union' AS area_type, 'Kalma' AS name, 'BD-UNION-3188' AS code
  UNION ALL
    SELECT 'BD-UPZ-355' AS parent_code, 'union' AS area_type, 'Adampur' AS name, 'BD-UNION-3189' AS code
  UNION ALL
    SELECT 'BD-UPZ-355' AS parent_code, 'union' AS area_type, 'Khyerpur-Abdullahpur' AS name, 'BD-UNION-3190' AS code
  UNION ALL
    SELECT 'BD-UPZ-355' AS parent_code, 'union' AS area_type, 'Purba Austagram' AS name, 'BD-UNION-3191' AS code
  UNION ALL
    SELECT 'BD-UPZ-356' AS parent_code, 'union' AS area_type, 'Gopdighi' AS name, 'BD-UNION-3192' AS code
  UNION ALL
    SELECT 'BD-UPZ-356' AS parent_code, 'union' AS area_type, 'Mithamoin' AS name, 'BD-UNION-3193' AS code
  UNION ALL
    SELECT 'BD-UPZ-356' AS parent_code, 'union' AS area_type, 'Dhaki' AS name, 'BD-UNION-3194' AS code
  UNION ALL
    SELECT 'BD-UPZ-356' AS parent_code, 'union' AS area_type, 'Ghagra' AS name, 'BD-UNION-3195' AS code
  UNION ALL
    SELECT 'BD-UPZ-356' AS parent_code, 'union' AS area_type, 'Keoarjore' AS name, 'BD-UNION-3196' AS code
  UNION ALL
    SELECT 'BD-UPZ-356' AS parent_code, 'union' AS area_type, 'Katkhal' AS name, 'BD-UNION-3197' AS code
  UNION ALL
    SELECT 'BD-UPZ-356' AS parent_code, 'union' AS area_type, 'Bairati' AS name, 'BD-UNION-3198' AS code
  UNION ALL
    SELECT 'BD-UPZ-357' AS parent_code, 'union' AS area_type, 'Chatirchar' AS name, 'BD-UNION-3199' AS code
  UNION ALL
    SELECT 'BD-UPZ-357' AS parent_code, 'union' AS area_type, 'Guroi' AS name, 'BD-UNION-3200' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;