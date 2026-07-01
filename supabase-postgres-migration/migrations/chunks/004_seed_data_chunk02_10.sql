INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-357' AS parent_code, 'union' AS area_type, 'Jaraitala' AS name, 'BD-UNION-3201' AS code
  UNION ALL
    SELECT 'BD-UPZ-357' AS parent_code, 'union' AS area_type, 'Nikli Sadar' AS name, 'BD-UNION-3202' AS code
  UNION ALL
    SELECT 'BD-UPZ-357' AS parent_code, 'union' AS area_type, 'Karpasa' AS name, 'BD-UNION-3203' AS code
  UNION ALL
    SELECT 'BD-UPZ-357' AS parent_code, 'union' AS area_type, 'Dampara' AS name, 'BD-UNION-3204' AS code
  UNION ALL
    SELECT 'BD-UPZ-357' AS parent_code, 'union' AS area_type, 'Singpur' AS name, 'BD-UNION-3205' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Balla' AS name, 'BD-UNION-3206' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Gala' AS name, 'BD-UNION-3207' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Chala' AS name, 'BD-UNION-3208' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Blara' AS name, 'BD-UNION-3209' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Harukandi' AS name, 'BD-UNION-3210' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Baira' AS name, 'BD-UNION-3211' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Ramkrishnapur' AS name, 'BD-UNION-3212' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Gopinathpur' AS name, 'BD-UNION-3213' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Kanchanpur' AS name, 'BD-UNION-3214' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Lacharagonj' AS name, 'BD-UNION-3215' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Sutalorie' AS name, 'BD-UNION-3216' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Dhulsura' AS name, 'BD-UNION-3217' AS code
  UNION ALL
    SELECT 'BD-UPZ-358' AS parent_code, 'union' AS area_type, 'Azimnagar' AS name, 'BD-UNION-3218' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Baried' AS name, 'BD-UNION-3219' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Dighulia' AS name, 'BD-UNION-3220' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Baliyati' AS name, 'BD-UNION-3221' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Dargram' AS name, 'BD-UNION-3222' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Tilli' AS name, 'BD-UNION-3223' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Hargaj' AS name, 'BD-UNION-3224' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Saturia' AS name, 'BD-UNION-3225' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Dhankora' AS name, 'BD-UNION-3226' AS code
  UNION ALL
    SELECT 'BD-UPZ-359' AS parent_code, 'union' AS area_type, 'Fukurhati' AS name, 'BD-UNION-3227' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Betila-Mitara' AS name, 'BD-UNION-3228' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Jagir' AS name, 'BD-UNION-3229' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Atigram' AS name, 'BD-UNION-3230' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Dighi' AS name, 'BD-UNION-3231' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Putile' AS name, 'BD-UNION-3232' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Hatipara' AS name, 'BD-UNION-3233' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Vararia' AS name, 'BD-UNION-3234' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Nbogram' AS name, 'BD-UNION-3235' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Garpara' AS name, 'BD-UNION-3236' AS code
  UNION ALL
    SELECT 'BD-UPZ-360' AS parent_code, 'union' AS area_type, 'Krishnapur' AS name, 'BD-UNION-3237' AS code
  UNION ALL
    SELECT 'BD-UPZ-361' AS parent_code, 'union' AS area_type, 'Paila' AS name, 'BD-UNION-3238' AS code
  UNION ALL
    SELECT 'BD-UPZ-361' AS parent_code, 'union' AS area_type, 'Shingzuri' AS name, 'BD-UNION-3239' AS code
  UNION ALL
    SELECT 'BD-UPZ-361' AS parent_code, 'union' AS area_type, 'Baliyakhora' AS name, 'BD-UNION-3240' AS code
  UNION ALL
    SELECT 'BD-UPZ-361' AS parent_code, 'union' AS area_type, 'Gior' AS name, 'BD-UNION-3241' AS code
  UNION ALL
    SELECT 'BD-UPZ-361' AS parent_code, 'union' AS area_type, 'Bartia' AS name, 'BD-UNION-3242' AS code
  UNION ALL
    SELECT 'BD-UPZ-361' AS parent_code, 'union' AS area_type, 'Baniazuri' AS name, 'BD-UNION-3243' AS code
  UNION ALL
    SELECT 'BD-UPZ-361' AS parent_code, 'union' AS area_type, 'Nalee' AS name, 'BD-UNION-3244' AS code
  UNION ALL
    SELECT 'BD-UPZ-362' AS parent_code, 'union' AS area_type, 'Teota' AS name, 'BD-UNION-3245' AS code
  UNION ALL
    SELECT 'BD-UPZ-362' AS parent_code, 'union' AS area_type, 'Utholi' AS name, 'BD-UNION-3246' AS code
  UNION ALL
    SELECT 'BD-UPZ-362' AS parent_code, 'union' AS area_type, 'Shibaloy' AS name, 'BD-UNION-3247' AS code
  UNION ALL
    SELECT 'BD-UPZ-362' AS parent_code, 'union' AS area_type, 'Ulayel' AS name, 'BD-UNION-3248' AS code
  UNION ALL
    SELECT 'BD-UPZ-362' AS parent_code, 'union' AS area_type, 'Aruoa' AS name, 'BD-UNION-3249' AS code
  UNION ALL
    SELECT 'BD-UPZ-362' AS parent_code, 'union' AS area_type, 'Mohadebpur' AS name, 'BD-UNION-3250' AS code
  UNION ALL
    SELECT 'BD-UPZ-362' AS parent_code, 'union' AS area_type, 'Shimulia' AS name, 'BD-UNION-3251' AS code
  UNION ALL
    SELECT 'BD-UPZ-363' AS parent_code, 'union' AS area_type, 'Charkataree' AS name, 'BD-UNION-3252' AS code
  UNION ALL
    SELECT 'BD-UPZ-363' AS parent_code, 'union' AS area_type, 'Bachamara' AS name, 'BD-UNION-3253' AS code
  UNION ALL
    SELECT 'BD-UPZ-363' AS parent_code, 'union' AS area_type, 'Baghutia' AS name, 'BD-UNION-3254' AS code
  UNION ALL
    SELECT 'BD-UPZ-363' AS parent_code, 'union' AS area_type, 'Zionpur' AS name, 'BD-UNION-3255' AS code
  UNION ALL
    SELECT 'BD-UPZ-363' AS parent_code, 'union' AS area_type, 'Khalshi' AS name, 'BD-UNION-3256' AS code
  UNION ALL
    SELECT 'BD-UPZ-363' AS parent_code, 'union' AS area_type, 'Chakmirpur' AS name, 'BD-UNION-3257' AS code
  UNION ALL
    SELECT 'BD-UPZ-363' AS parent_code, 'union' AS area_type, 'Klia' AS name, 'BD-UNION-3258' AS code
  UNION ALL
    SELECT 'BD-UPZ-363' AS parent_code, 'union' AS area_type, 'Dhamswar' AS name, 'BD-UNION-3259' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Buyra' AS name, 'BD-UNION-3260' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Talebpur' AS name, 'BD-UNION-3261' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Singiar' AS name, 'BD-UNION-3262' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Baldhara' AS name, 'BD-UNION-3263' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Zamsha' AS name, 'BD-UNION-3264' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Charigram' AS name, 'BD-UNION-3265' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Shayesta' AS name, 'BD-UNION-3266' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Joymonto' AS name, 'BD-UNION-3267' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Dhalla' AS name, 'BD-UNION-3268' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Jamirta' AS name, 'BD-UNION-3269' AS code
  UNION ALL
    SELECT 'BD-UPZ-364' AS parent_code, 'union' AS area_type, 'Chandhar' AS name, 'BD-UNION-3270' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Savar' AS name, 'BD-UNION-3271' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Birulia' AS name, 'BD-UNION-3272' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Dhamsona' AS name, 'BD-UNION-3273' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Shimulia' AS name, 'BD-UNION-3274' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Ashulia' AS name, 'BD-UNION-3275' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Yearpur' AS name, 'BD-UNION-3276' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Vakurta' AS name, 'BD-UNION-3277' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Pathalia' AS name, 'BD-UNION-3278' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Bongaon' AS name, 'BD-UNION-3279' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Kaundia' AS name, 'BD-UNION-3280' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Tetuljhora' AS name, 'BD-UNION-3281' AS code
  UNION ALL
    SELECT 'BD-UPZ-365' AS parent_code, 'union' AS area_type, 'Aminbazar' AS name, 'BD-UNION-3282' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Chauhat' AS name, 'BD-UNION-3283' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Amta' AS name, 'BD-UNION-3284' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Balia' AS name, 'BD-UNION-3285' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Jadabpur' AS name, 'BD-UNION-3286' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Baisakanda' AS name, 'BD-UNION-3287' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Kushura' AS name, 'BD-UNION-3288' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Gangutia' AS name, 'BD-UNION-3289' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Sanora' AS name, 'BD-UNION-3290' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Sutipara' AS name, 'BD-UNION-3291' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Sombhag' AS name, 'BD-UNION-3292' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Vararia' AS name, 'BD-UNION-3293' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Dhamrai' AS name, 'BD-UNION-3294' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Kulla' AS name, 'BD-UNION-3295' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Rowail' AS name, 'BD-UNION-3296' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Suapur' AS name, 'BD-UNION-3297' AS code
  UNION ALL
    SELECT 'BD-UPZ-366' AS parent_code, 'union' AS area_type, 'Nannar' AS name, 'BD-UNION-3298' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Hazratpur' AS name, 'BD-UNION-3299' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Kalatia' AS name, 'BD-UNION-3300' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Taranagar' AS name, 'BD-UNION-3301' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Sakta' AS name, 'BD-UNION-3302' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Ruhitpur' AS name, 'BD-UNION-3303' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Basta' AS name, 'BD-UNION-3304' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Kalindi' AS name, 'BD-UNION-3305' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Zinzira' AS name, 'BD-UNION-3306' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Suvadda' AS name, 'BD-UNION-3307' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Taghoria' AS name, 'BD-UNION-3308' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Konda' AS name, 'BD-UNION-3309' AS code
  UNION ALL
    SELECT 'BD-UPZ-367' AS parent_code, 'union' AS area_type, 'Aganagar' AS name, 'BD-UNION-3310' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Shikaripara' AS name, 'BD-UNION-3311' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Joykrishnapur' AS name, 'BD-UNION-3312' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Baruakhali' AS name, 'BD-UNION-3313' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Nayansree' AS name, 'BD-UNION-3314' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Sholla' AS name, 'BD-UNION-3315' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Jantrail' AS name, 'BD-UNION-3316' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Bandura' AS name, 'BD-UNION-3317' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Kalakopa' AS name, 'BD-UNION-3318' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Bakshanagar' AS name, 'BD-UNION-3319' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Barrah' AS name, 'BD-UNION-3320' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Kailail' AS name, 'BD-UNION-3321' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Agla' AS name, 'BD-UNION-3322' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Galimpur' AS name, 'BD-UNION-3323' AS code
  UNION ALL
    SELECT 'BD-UPZ-368' AS parent_code, 'union' AS area_type, 'Churain' AS name, 'BD-UNION-3324' AS code
  UNION ALL
    SELECT 'BD-UPZ-369' AS parent_code, 'union' AS area_type, 'Nayabari' AS name, 'BD-UNION-3325' AS code
  UNION ALL
    SELECT 'BD-UPZ-369' AS parent_code, 'union' AS area_type, 'Kusumhathi' AS name, 'BD-UNION-3326' AS code
  UNION ALL
    SELECT 'BD-UPZ-369' AS parent_code, 'union' AS area_type, 'Raipara' AS name, 'BD-UNION-3327' AS code
  UNION ALL
    SELECT 'BD-UPZ-369' AS parent_code, 'union' AS area_type, 'Sutarpara' AS name, 'BD-UNION-3328' AS code
  UNION ALL
    SELECT 'BD-UPZ-369' AS parent_code, 'union' AS area_type, 'Narisha' AS name, 'BD-UNION-3329' AS code
  UNION ALL
    SELECT 'BD-UPZ-369' AS parent_code, 'union' AS area_type, 'Muksudpur' AS name, 'BD-UNION-3330' AS code
  UNION ALL
    SELECT 'BD-UPZ-369' AS parent_code, 'union' AS area_type, 'Mahmudpur' AS name, 'BD-UNION-3331' AS code
  UNION ALL
    SELECT 'BD-UPZ-369' AS parent_code, 'union' AS area_type, 'Bilaspur' AS name, 'BD-UNION-3332' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Rampal' AS name, 'BD-UNION-3333' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Panchashar' AS name, 'BD-UNION-3334' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Bajrajogini' AS name, 'BD-UNION-3335' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Mohakali' AS name, 'BD-UNION-3336' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Charkewar' AS name, 'BD-UNION-3337' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Mollakandi' AS name, 'BD-UNION-3338' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Adhara' AS name, 'BD-UNION-3339' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Shiloy' AS name, 'BD-UNION-3340' AS code
  UNION ALL
    SELECT 'BD-UPZ-370' AS parent_code, 'union' AS area_type, 'Banglabazar' AS name, 'BD-UNION-3341' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Baraikhali' AS name, 'BD-UNION-3342' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Hashara' AS name, 'BD-UNION-3343' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Birtara' AS name, 'BD-UNION-3344' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Shologhor' AS name, 'BD-UNION-3345' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Sreenagar' AS name, 'BD-UNION-3346' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Patabhog' AS name, 'BD-UNION-3347' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Shamshiddi' AS name, 'BD-UNION-3348' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Kolapara' AS name, 'BD-UNION-3349' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Vaggakol' AS name, 'BD-UNION-3350' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Bagra' AS name, 'BD-UNION-3351' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Rarikhal' AS name, 'BD-UNION-3352' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Kukutia' AS name, 'BD-UNION-3353' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Atpara' AS name, 'BD-UNION-3354' AS code
  UNION ALL
    SELECT 'BD-UPZ-371' AS parent_code, 'union' AS area_type, 'Tantor' AS name, 'BD-UNION-3355' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Chitracoat' AS name, 'BD-UNION-3356' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Sekhornagar' AS name, 'BD-UNION-3357' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Rajanagar' AS name, 'BD-UNION-3358' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Keyain' AS name, 'BD-UNION-3359' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Basail' AS name, 'BD-UNION-3360' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Baluchar' AS name, 'BD-UNION-3361' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Latabdi' AS name, 'BD-UNION-3362' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Rasunia' AS name, 'BD-UNION-3363' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Ichhapura' AS name, 'BD-UNION-3364' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Bairagadi' AS name, 'BD-UNION-3365' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Malkhanagar' AS name, 'BD-UNION-3366' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Madhypara' AS name, 'BD-UNION-3367' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Kola' AS name, 'BD-UNION-3368' AS code
  UNION ALL
    SELECT 'BD-UPZ-372' AS parent_code, 'union' AS area_type, 'Joyinshar' AS name, 'BD-UNION-3369' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Medinimandal' AS name, 'BD-UNION-3370' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Kumarbhog' AS name, 'BD-UNION-3371' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Haldia' AS name, 'BD-UNION-3372' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Kanaksar' AS name, 'BD-UNION-3373' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Lohajang-Teotia' AS name, 'BD-UNION-3374' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Bejgaon' AS name, 'BD-UNION-3375' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Baultoli' AS name, 'BD-UNION-3376' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Khidirpara' AS name, 'BD-UNION-3377' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Gaodia' AS name, 'BD-UNION-3378' AS code
  UNION ALL
    SELECT 'BD-UPZ-373' AS parent_code, 'union' AS area_type, 'Kalma' AS name, 'BD-UNION-3379' AS code
  UNION ALL
    SELECT 'BD-UPZ-374' AS parent_code, 'union' AS area_type, 'Gajaria' AS name, 'BD-UNION-3380' AS code
  UNION ALL
    SELECT 'BD-UPZ-374' AS parent_code, 'union' AS area_type, 'Baushia' AS name, 'BD-UNION-3381' AS code
  UNION ALL
    SELECT 'BD-UPZ-374' AS parent_code, 'union' AS area_type, 'Vaberchar' AS name, 'BD-UNION-3382' AS code
  UNION ALL
    SELECT 'BD-UPZ-374' AS parent_code, 'union' AS area_type, 'Baluakandi' AS name, 'BD-UNION-3383' AS code
  UNION ALL
    SELECT 'BD-UPZ-374' AS parent_code, 'union' AS area_type, 'Tengarchar' AS name, 'BD-UNION-3384' AS code
  UNION ALL
    SELECT 'BD-UPZ-374' AS parent_code, 'union' AS area_type, 'Hosendee' AS name, 'BD-UNION-3385' AS code
  UNION ALL
    SELECT 'BD-UPZ-374' AS parent_code, 'union' AS area_type, 'Guagachia' AS name, 'BD-UNION-3386' AS code
  UNION ALL
    SELECT 'BD-UPZ-374' AS parent_code, 'union' AS area_type, 'Imampur' AS name, 'BD-UNION-3387' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Betka' AS name, 'BD-UNION-3388' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Abdullapur' AS name, 'BD-UNION-3389' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Sonarong Tongibari' AS name, 'BD-UNION-3390' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Autshahi' AS name, 'BD-UNION-3391' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Arial Baligaon' AS name, 'BD-UNION-3392' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Dhipur' AS name, 'BD-UNION-3393' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Kathadia Shimolia' AS name, 'BD-UNION-3394' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Joslong' AS name, 'BD-UNION-3395' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Panchgaon' AS name, 'BD-UNION-3396' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Kamarkhara' AS name, 'BD-UNION-3397' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Hasailbanari' AS name, 'BD-UNION-3398' AS code
  UNION ALL
    SELECT 'BD-UPZ-375' AS parent_code, 'union' AS area_type, 'Dighirpar' AS name, 'BD-UNION-3399' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Mijanpur' AS name, 'BD-UNION-3400' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Borat' AS name, 'BD-UNION-3401' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Chandoni' AS name, 'BD-UNION-3402' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Khangonj' AS name, 'BD-UNION-3403' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Banibaha' AS name, 'BD-UNION-3404' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Dadshee' AS name, 'BD-UNION-3405' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Mulghar' AS name, 'BD-UNION-3406' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Basantapur' AS name, 'BD-UNION-3407' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Khankhanapur' AS name, 'BD-UNION-3408' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Alipur' AS name, 'BD-UNION-3409' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Ramkantapur' AS name, 'BD-UNION-3410' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Shahidwahabpur' AS name, 'BD-UNION-3411' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Panchuria' AS name, 'BD-UNION-3412' AS code
  UNION ALL
    SELECT 'BD-UPZ-376' AS parent_code, 'union' AS area_type, 'Sultanpur' AS name, 'BD-UNION-3413' AS code
  UNION ALL
    SELECT 'BD-UPZ-377' AS parent_code, 'union' AS area_type, 'Doulatdia' AS name, 'BD-UNION-3414' AS code
  UNION ALL
    SELECT 'BD-UPZ-377' AS parent_code, 'union' AS area_type, 'Debugram' AS name, 'BD-UNION-3415' AS code
  UNION ALL
    SELECT 'BD-UPZ-377' AS parent_code, 'union' AS area_type, 'Uzancar' AS name, 'BD-UNION-3416' AS code
  UNION ALL
    SELECT 'BD-UPZ-377' AS parent_code, 'union' AS area_type, 'Chotovakla' AS name, 'BD-UNION-3417' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Bahadurpur' AS name, 'BD-UNION-3418' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Habashpur' AS name, 'BD-UNION-3419' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Jashai' AS name, 'BD-UNION-3420' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Babupara' AS name, 'BD-UNION-3421' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Mourat' AS name, 'BD-UNION-3422' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Patta' AS name, 'BD-UNION-3423' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Sarisha' AS name, 'BD-UNION-3424' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Kalimahar' AS name, 'BD-UNION-3425' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Kasbamajhail' AS name, 'BD-UNION-3426' AS code
  UNION ALL
    SELECT 'BD-UPZ-378' AS parent_code, 'union' AS area_type, 'Machhpara' AS name, 'BD-UNION-3427' AS code
  UNION ALL
    SELECT 'BD-UPZ-379' AS parent_code, 'union' AS area_type, 'Islampur' AS name, 'BD-UNION-3428' AS code
  UNION ALL
    SELECT 'BD-UPZ-379' AS parent_code, 'union' AS area_type, 'Baharpur' AS name, 'BD-UNION-3429' AS code
  UNION ALL
    SELECT 'BD-UPZ-379' AS parent_code, 'union' AS area_type, 'Nawabpur' AS name, 'BD-UNION-3430' AS code
  UNION ALL
    SELECT 'BD-UPZ-379' AS parent_code, 'union' AS area_type, 'Narua' AS name, 'BD-UNION-3431' AS code
  UNION ALL
    SELECT 'BD-UPZ-379' AS parent_code, 'union' AS area_type, 'Baliakandi' AS name, 'BD-UNION-3432' AS code
  UNION ALL
    SELECT 'BD-UPZ-379' AS parent_code, 'union' AS area_type, 'Janjal' AS name, 'BD-UNION-3433' AS code
  UNION ALL
    SELECT 'BD-UPZ-379' AS parent_code, 'union' AS area_type, 'Jamalpur' AS name, 'BD-UNION-3434' AS code
  UNION ALL
    SELECT 'BD-UPZ-380' AS parent_code, 'union' AS area_type, 'Kalukhali' AS name, 'BD-UNION-3435' AS code
  UNION ALL
    SELECT 'BD-UPZ-380' AS parent_code, 'union' AS area_type, 'Ratandia' AS name, 'BD-UNION-3436' AS code
  UNION ALL
    SELECT 'BD-UPZ-380' AS parent_code, 'union' AS area_type, 'Kalikapur' AS name, 'BD-UNION-3437' AS code
  UNION ALL
    SELECT 'BD-UPZ-380' AS parent_code, 'union' AS area_type, 'Boalia' AS name, 'BD-UNION-3438' AS code
  UNION ALL
    SELECT 'BD-UPZ-380' AS parent_code, 'union' AS area_type, 'Majbari' AS name, 'BD-UNION-3439' AS code
  UNION ALL
    SELECT 'BD-UPZ-380' AS parent_code, 'union' AS area_type, 'Madapur' AS name, 'BD-UNION-3440' AS code
  UNION ALL
    SELECT 'BD-UPZ-380' AS parent_code, 'union' AS area_type, 'Shawrail' AS name, 'BD-UNION-3441' AS code
  UNION ALL
    SELECT 'BD-UPZ-380' AS parent_code, 'union' AS area_type, 'Mrigi' AS name, 'BD-UNION-3442' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Sirkhara' AS name, 'BD-UNION-3443' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Bahadurpur' AS name, 'BD-UNION-3444' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Kunia' AS name, 'BD-UNION-3445' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Peyarpur' AS name, 'BD-UNION-3446' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Kandua' AS name, 'BD-UNION-3447' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Mastofapur' AS name, 'BD-UNION-3448' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Dudkhali' AS name, 'BD-UNION-3449' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Kalikapur' AS name, 'BD-UNION-3450' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Chilarchar' AS name, 'BD-UNION-3451' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Panchkhola' AS name, 'BD-UNION-3452' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Ghatmajhi' AS name, 'BD-UNION-3453' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Jhaoudi' AS name, 'BD-UNION-3454' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Khoajpur' AS name, 'BD-UNION-3455' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Rasti' AS name, 'BD-UNION-3456' AS code
  UNION ALL
    SELECT 'BD-UPZ-381' AS parent_code, 'union' AS area_type, 'Dhurail' AS name, 'BD-UNION-3457' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Shibchar' AS name, 'BD-UNION-3458' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Ditiyakhando' AS name, 'BD-UNION-3459' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Nilokhe' AS name, 'BD-UNION-3460' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Bandarkhola' AS name, 'BD-UNION-3461' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Charjanazat' AS name, 'BD-UNION-3462' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Madbarerchar' AS name, 'BD-UNION-3463' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Panchar' AS name, 'BD-UNION-3464' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Sannasirchar' AS name, 'BD-UNION-3465' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Kathalbari' AS name, 'BD-UNION-3466' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Kutubpur' AS name, 'BD-UNION-3467' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Kadirpur' AS name, 'BD-UNION-3468' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Vhandarikandi' AS name, 'BD-UNION-3469' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Bahertala South' AS name, 'BD-UNION-3470' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Baheratala North' AS name, 'BD-UNION-3471' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Baskandi' AS name, 'BD-UNION-3472' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Umedpur' AS name, 'BD-UNION-3473' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Vhadrasion' AS name, 'BD-UNION-3474' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Shiruail' AS name, 'BD-UNION-3475' AS code
  UNION ALL
    SELECT 'BD-UPZ-382' AS parent_code, 'union' AS area_type, 'Dattapara' AS name, 'BD-UNION-3476' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Alinagar' AS name, 'BD-UNION-3477' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Baligram' AS name, 'BD-UNION-3478' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Basgari' AS name, 'BD-UNION-3479' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Chardoulatkhan' AS name, 'BD-UNION-3480' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Dashar' AS name, 'BD-UNION-3481' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Enayetnagor' AS name, 'BD-UNION-3482' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Gopalpur' AS name, 'BD-UNION-3483' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Koyaria' AS name, 'BD-UNION-3484' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Kazibakai' AS name, 'BD-UNION-3485' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Laxmipur' AS name, 'BD-UNION-3486' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Nabogram' AS name, 'BD-UNION-3487' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Ramjanpur' AS name, 'BD-UNION-3488' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Shahebrampur' AS name, 'BD-UNION-3489' AS code
  UNION ALL
    SELECT 'BD-UPZ-383' AS parent_code, 'union' AS area_type, 'Shikarmongol' AS name, 'BD-UNION-3490' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Haridasdi-Mahendrodi' AS name, 'BD-UNION-3491' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Kadambari' AS name, 'BD-UNION-3492' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Bajitpur' AS name, 'BD-UNION-3493' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Amgram' AS name, 'BD-UNION-3494' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Rajoir' AS name, 'BD-UNION-3495' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Khaliya' AS name, 'BD-UNION-3496' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Ishibpur' AS name, 'BD-UNION-3497' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Badarpasa' AS name, 'BD-UNION-3498' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Kabirajpur' AS name, 'BD-UNION-3499' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Hosenpur' AS name, 'BD-UNION-3500' AS code
  UNION ALL
    SELECT 'BD-UPZ-384' AS parent_code, 'union' AS area_type, 'Paikpara' AS name, 'BD-UNION-3501' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Jalalabad' AS name, 'BD-UNION-3502' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Shuktail' AS name, 'BD-UNION-3503' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Chandradighalia' AS name, 'BD-UNION-3504' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Gopinathpur' AS name, 'BD-UNION-3505' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Paikkandi' AS name, 'BD-UNION-3506' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Urfi' AS name, 'BD-UNION-3507' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Lotifpur' AS name, 'BD-UNION-3508' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Satpar' AS name, 'BD-UNION-3509' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Sahapur' AS name, 'BD-UNION-3510' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Horidaspur' AS name, 'BD-UNION-3511' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Ulpur' AS name, 'BD-UNION-3512' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Nizra' AS name, 'BD-UNION-3513' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Karpara' AS name, 'BD-UNION-3514' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-3515' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Kajulia' AS name, 'BD-UNION-3516' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Majhigati' AS name, 'BD-UNION-3517' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Roghunathpur' AS name, 'BD-UNION-3518' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Gobra' AS name, 'BD-UNION-3519' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Borashi' AS name, 'BD-UNION-3520' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Kati' AS name, 'BD-UNION-3521' AS code
  UNION ALL
    SELECT 'BD-UPZ-385' AS parent_code, 'union' AS area_type, 'Boultali' AS name, 'BD-UNION-3522' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Kashiani' AS name, 'BD-UNION-3523' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Hatiara' AS name, 'BD-UNION-3524' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Fukura' AS name, 'BD-UNION-3525' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Rajpat' AS name, 'BD-UNION-3526' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Bethuri' AS name, 'BD-UNION-3527' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Nijamkandi' AS name, 'BD-UNION-3528' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Sajail' AS name, 'BD-UNION-3529' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Mamudpur' AS name, 'BD-UNION-3530' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Maheshpur' AS name, 'BD-UNION-3531' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Orakandia' AS name, 'BD-UNION-3532' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Parulia' AS name, 'BD-UNION-3533' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Ratail' AS name, 'BD-UNION-3534' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Puisur' AS name, 'BD-UNION-3535' AS code
  UNION ALL
    SELECT 'BD-UPZ-386' AS parent_code, 'union' AS area_type, 'Singa' AS name, 'BD-UNION-3536' AS code
  UNION ALL
    SELECT 'BD-UPZ-387' AS parent_code, 'union' AS area_type, 'Kushli' AS name, 'BD-UNION-3537' AS code
  UNION ALL
    SELECT 'BD-UPZ-387' AS parent_code, 'union' AS area_type, 'Gopalpur' AS name, 'BD-UNION-3538' AS code
  UNION ALL
    SELECT 'BD-UPZ-387' AS parent_code, 'union' AS area_type, 'Patgati' AS name, 'BD-UNION-3539' AS code
  UNION ALL
    SELECT 'BD-UPZ-387' AS parent_code, 'union' AS area_type, 'Borni' AS name, 'BD-UNION-3540' AS code
  UNION ALL
    SELECT 'BD-UPZ-387' AS parent_code, 'union' AS area_type, 'Dumaria' AS name, 'BD-UNION-3541' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Sadullapur' AS name, 'BD-UNION-3542' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Ramshil' AS name, 'BD-UNION-3543' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Bandhabari' AS name, 'BD-UNION-3544' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Kolabari' AS name, 'BD-UNION-3545' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Kushla' AS name, 'BD-UNION-3546' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Amtoli' AS name, 'BD-UNION-3547' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Pinjuri' AS name, 'BD-UNION-3548' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Ghaghor' AS name, 'BD-UNION-3549' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Radhaganj' AS name, 'BD-UNION-3550' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Hiron' AS name, 'BD-UNION-3551' AS code
  UNION ALL
    SELECT 'BD-UPZ-388' AS parent_code, 'union' AS area_type, 'Kandi' AS name, 'BD-UNION-3552' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Ujani' AS name, 'BD-UNION-3553' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Nanikhir' AS name, 'BD-UNION-3554' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Dignagar' AS name, 'BD-UNION-3555' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Poshargati' AS name, 'BD-UNION-3556' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Gobindopur' AS name, 'BD-UNION-3557' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Khandarpara' AS name, 'BD-UNION-3558' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Bohugram' AS name, 'BD-UNION-3559' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Banshbaria' AS name, 'BD-UNION-3560' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Vabrashur' AS name, 'BD-UNION-3561' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Moharajpur' AS name, 'BD-UNION-3562' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Batikamari' AS name, 'BD-UNION-3563' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Jalirpar' AS name, 'BD-UNION-3564' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Raghdi' AS name, 'BD-UNION-3565' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Gohala' AS name, 'BD-UNION-3566' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Mochna' AS name, 'BD-UNION-3567' AS code
  UNION ALL
    SELECT 'BD-UPZ-389' AS parent_code, 'union' AS area_type, 'Kashalia' AS name, 'BD-UNION-3568' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Ishangopalpur' AS name, 'BD-UNION-3569' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Charmadbdia' AS name, 'BD-UNION-3570' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Aliabad' AS name, 'BD-UNION-3571' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Uttarchannel' AS name, 'BD-UNION-3572' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Decreerchar' AS name, 'BD-UNION-3573' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Majchar' AS name, 'BD-UNION-3574' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Krishnanagar' AS name, 'BD-UNION-3575' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Ambikapur' AS name, 'BD-UNION-3576' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Kanaipur' AS name, 'BD-UNION-3577' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Kaijuri' AS name, 'BD-UNION-3578' AS code
  UNION ALL
    SELECT 'BD-UPZ-390' AS parent_code, 'union' AS area_type, 'Greda' AS name, 'BD-UNION-3579' AS code
  UNION ALL
    SELECT 'BD-UPZ-391' AS parent_code, 'union' AS area_type, 'Buraich' AS name, 'BD-UNION-3580' AS code
  UNION ALL
    SELECT 'BD-UPZ-391' AS parent_code, 'union' AS area_type, 'Alfadanga' AS name, 'BD-UNION-3581' AS code
  UNION ALL
    SELECT 'BD-UPZ-391' AS parent_code, 'union' AS area_type, 'Tagarbanda' AS name, 'BD-UNION-3582' AS code
  UNION ALL
    SELECT 'BD-UPZ-391' AS parent_code, 'union' AS area_type, 'Bana' AS name, 'BD-UNION-3583' AS code
  UNION ALL
    SELECT 'BD-UPZ-391' AS parent_code, 'union' AS area_type, 'Panchuria' AS name, 'BD-UNION-3584' AS code
  UNION ALL
    SELECT 'BD-UPZ-391' AS parent_code, 'union' AS area_type, 'Gopalpur' AS name, 'BD-UNION-3585' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Boalmari' AS name, 'BD-UNION-3586' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Dadpur' AS name, 'BD-UNION-3587' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Chatul' AS name, 'BD-UNION-3588' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Ghoshpur' AS name, 'BD-UNION-3589' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Gunbaha' AS name, 'BD-UNION-3590' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Chandpur' AS name, 'BD-UNION-3591' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Parameshwardi' AS name, 'BD-UNION-3592' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Satair' AS name, 'BD-UNION-3593' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Rupapat' AS name, 'BD-UNION-3594' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Shekhar' AS name, 'BD-UNION-3595' AS code
  UNION ALL
    SELECT 'BD-UPZ-392' AS parent_code, 'union' AS area_type, 'Moyna' AS name, 'BD-UNION-3596' AS code
  UNION ALL
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Char Bisnopur' AS name, 'BD-UNION-3597' AS code
  UNION ALL
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Akoter Char' AS name, 'BD-UNION-3598' AS code
  UNION ALL
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Char Nasirpur' AS name, 'BD-UNION-3599' AS code
  UNION ALL
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Narikel Bariya' AS name, 'BD-UNION-3600' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;