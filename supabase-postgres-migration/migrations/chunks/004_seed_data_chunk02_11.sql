INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Bhashanchar' AS name, 'BD-UNION-3601' AS code
  UNION ALL
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Krishnapur' AS name, 'BD-UNION-3602' AS code
  UNION ALL
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Sadarpur' AS name, 'BD-UNION-3603' AS code
  UNION ALL
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Char Manair' AS name, 'BD-UNION-3604' AS code
  UNION ALL
    SELECT 'BD-UPZ-393' AS parent_code, 'union' AS area_type, 'Dhaukhali' AS name, 'BD-UNION-3605' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Charjashordi' AS name, 'BD-UNION-3606' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Purapara' AS name, 'BD-UNION-3607' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Laskardia' AS name, 'BD-UNION-3608' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Ramnagar' AS name, 'BD-UNION-3609' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Kaichail' AS name, 'BD-UNION-3610' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Talma' AS name, 'BD-UNION-3611' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Fulsuti' AS name, 'BD-UNION-3612' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Dangi' AS name, 'BD-UNION-3613' AS code
  UNION ALL
    SELECT 'BD-UPZ-394' AS parent_code, 'union' AS area_type, 'Kodalia Shohidnagar' AS name, 'BD-UNION-3614' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Gharua' AS name, 'BD-UNION-3615' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Nurullagonj' AS name, 'BD-UNION-3616' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Manikdha' AS name, 'BD-UNION-3617' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Kawlibera' AS name, 'BD-UNION-3618' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Nasirabad' AS name, 'BD-UNION-3619' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Tujerpur' AS name, 'BD-UNION-3620' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Algi' AS name, 'BD-UNION-3621' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Chumurdi' AS name, 'BD-UNION-3622' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Kalamridha' AS name, 'BD-UNION-3623' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Azimnagor' AS name, 'BD-UNION-3624' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Chandra' AS name, 'BD-UNION-3625' AS code
  UNION ALL
    SELECT 'BD-UPZ-395' AS parent_code, 'union' AS area_type, 'Hamirdi' AS name, 'BD-UNION-3626' AS code
  UNION ALL
    SELECT 'BD-UPZ-396' AS parent_code, 'union' AS area_type, 'Gazirtek' AS name, 'BD-UNION-3627' AS code
  UNION ALL
    SELECT 'BD-UPZ-396' AS parent_code, 'union' AS area_type, 'Char Bhadrasan' AS name, 'BD-UNION-3628' AS code
  UNION ALL
    SELECT 'BD-UPZ-396' AS parent_code, 'union' AS area_type, 'Char Harirampur' AS name, 'BD-UNION-3629' AS code
  UNION ALL
    SELECT 'BD-UPZ-396' AS parent_code, 'union' AS area_type, 'Char Jahukanda' AS name, 'BD-UNION-3630' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Madhukhali' AS name, 'BD-UNION-3631' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Jahapur' AS name, 'BD-UNION-3632' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Gazna' AS name, 'BD-UNION-3633' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Megchami' AS name, 'BD-UNION-3634' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Raipur' AS name, 'BD-UNION-3635' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Bagat' AS name, 'BD-UNION-3636' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Dumain' AS name, 'BD-UNION-3637' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Nowpara' AS name, 'BD-UNION-3638' AS code
  UNION ALL
    SELECT 'BD-UPZ-397' AS parent_code, 'union' AS area_type, 'Kamarkhali' AS name, 'BD-UNION-3639' AS code
  UNION ALL
    SELECT 'BD-UPZ-398' AS parent_code, 'union' AS area_type, 'Bhawal' AS name, 'BD-UNION-3640' AS code
  UNION ALL
    SELECT 'BD-UPZ-398' AS parent_code, 'union' AS area_type, 'Atghar' AS name, 'BD-UNION-3641' AS code
  UNION ALL
    SELECT 'BD-UPZ-398' AS parent_code, 'union' AS area_type, 'Mazadia' AS name, 'BD-UNION-3642' AS code
  UNION ALL
    SELECT 'BD-UPZ-398' AS parent_code, 'union' AS area_type, 'Ballabhdi' AS name, 'BD-UNION-3643' AS code
  UNION ALL
    SELECT 'BD-UPZ-398' AS parent_code, 'union' AS area_type, 'Gatti' AS name, 'BD-UNION-3644' AS code
  UNION ALL
    SELECT 'BD-UPZ-398' AS parent_code, 'union' AS area_type, 'Jadunandi' AS name, 'BD-UNION-3645' AS code
  UNION ALL
    SELECT 'BD-UPZ-398' AS parent_code, 'union' AS area_type, 'Ramkantapur' AS name, 'BD-UNION-3646' AS code
  UNION ALL
    SELECT 'BD-UPZ-398' AS parent_code, 'union' AS area_type, 'Sonapur' AS name, 'BD-UNION-3647' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Panchagarh Sadar' AS name, 'BD-UNION-3648' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Satmara' AS name, 'BD-UNION-3649' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Amarkhana' AS name, 'BD-UNION-3650' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Haribhasa' AS name, 'BD-UNION-3651' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Chaklahat' AS name, 'BD-UNION-3652' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Hafizabad' AS name, 'BD-UNION-3653' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Kamat Kajol Dighi' AS name, 'BD-UNION-3654' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Dhakkamara' AS name, 'BD-UNION-3655' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Magura' AS name, 'BD-UNION-3656' AS code
  UNION ALL
    SELECT 'BD-UPZ-399' AS parent_code, 'union' AS area_type, 'Garinabari' AS name, 'BD-UNION-3657' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Chilahati' AS name, 'BD-UNION-3658' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Shaldanga' AS name, 'BD-UNION-3659' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Debiganj Sadar' AS name, 'BD-UNION-3660' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Pamuli' AS name, 'BD-UNION-3661' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Sundardighi' AS name, 'BD-UNION-3662' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Sonahar Mollikadaha' AS name, 'BD-UNION-3663' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Tepriganj' AS name, 'BD-UNION-3664' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Dandopal' AS name, 'BD-UNION-3665' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Debiduba' AS name, 'BD-UNION-3666' AS code
  UNION ALL
    SELECT 'BD-UPZ-400' AS parent_code, 'union' AS area_type, 'Chengthi Hazra Danga' AS name, 'BD-UNION-3667' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Jholaishal Shiri' AS name, 'BD-UNION-3668' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Moidandighi' AS name, 'BD-UNION-3669' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Banghari' AS name, 'BD-UNION-3670' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Kajoldighi Kaligonj' AS name, 'BD-UNION-3671' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Boroshoshi' AS name, 'BD-UNION-3672' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Chandanbari' AS name, 'BD-UNION-3673' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Marea Bamonhat' AS name, 'BD-UNION-3674' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Boda' AS name, 'BD-UNION-3675' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Sakoa' AS name, 'BD-UNION-3676' AS code
  UNION ALL
    SELECT 'BD-UPZ-401' AS parent_code, 'union' AS area_type, 'Pachpir' AS name, 'BD-UNION-3677' AS code
  UNION ALL
    SELECT 'BD-UPZ-402' AS parent_code, 'union' AS area_type, 'Mirgapur' AS name, 'BD-UNION-3678' AS code
  UNION ALL
    SELECT 'BD-UPZ-402' AS parent_code, 'union' AS area_type, 'Radhanagar' AS name, 'BD-UNION-3679' AS code
  UNION ALL
    SELECT 'BD-UPZ-402' AS parent_code, 'union' AS area_type, 'Toria' AS name, 'BD-UNION-3680' AS code
  UNION ALL
    SELECT 'BD-UPZ-402' AS parent_code, 'union' AS area_type, 'Balarampur' AS name, 'BD-UNION-3681' AS code
  UNION ALL
    SELECT 'BD-UPZ-402' AS parent_code, 'union' AS area_type, 'Alowakhowa' AS name, 'BD-UNION-3682' AS code
  UNION ALL
    SELECT 'BD-UPZ-402' AS parent_code, 'union' AS area_type, 'Dhamor' AS name, 'BD-UNION-3683' AS code
  UNION ALL
    SELECT 'BD-UPZ-403' AS parent_code, 'union' AS area_type, 'Banglabandha' AS name, 'BD-UNION-3684' AS code
  UNION ALL
    SELECT 'BD-UPZ-403' AS parent_code, 'union' AS area_type, 'Bhojoanpur' AS name, 'BD-UNION-3685' AS code
  UNION ALL
    SELECT 'BD-UPZ-403' AS parent_code, 'union' AS area_type, 'Bhojoanpur #3686' AS name, 'BD-UNION-3686' AS code
  UNION ALL
    SELECT 'BD-UPZ-403' AS parent_code, 'union' AS area_type, 'Buraburi' AS name, 'BD-UNION-3687' AS code
  UNION ALL
    SELECT 'BD-UPZ-403' AS parent_code, 'union' AS area_type, 'Debnagar' AS name, 'BD-UNION-3688' AS code
  UNION ALL
    SELECT 'BD-UPZ-403' AS parent_code, 'union' AS area_type, 'Salbahan' AS name, 'BD-UNION-3689' AS code
  UNION ALL
    SELECT 'BD-UPZ-403' AS parent_code, 'union' AS area_type, 'Tentulia' AS name, 'BD-UNION-3690' AS code
  UNION ALL
    SELECT 'BD-UPZ-403' AS parent_code, 'union' AS area_type, 'Timaihat' AS name, 'BD-UNION-3691' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Joypur' AS name, 'BD-UNION-3692' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Binodnagar' AS name, 'BD-UNION-3693' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Golapgonj' AS name, 'BD-UNION-3694' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Shalkhuria' AS name, 'BD-UNION-3695' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Putimara' AS name, 'BD-UNION-3696' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Bhaduria' AS name, 'BD-UNION-3697' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Daudpur' AS name, 'BD-UNION-3698' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Mahmudpur' AS name, 'BD-UNION-3699' AS code
  UNION ALL
    SELECT 'BD-UPZ-404' AS parent_code, 'union' AS area_type, 'Kushdaha' AS name, 'BD-UNION-3700' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Shibrampur' AS name, 'BD-UNION-3701' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Polashbari' AS name, 'BD-UNION-3702' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Shatagram' AS name, 'BD-UNION-3703' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Paltapur' AS name, 'BD-UNION-3704' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Sujalpur' AS name, 'BD-UNION-3705' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Nijpara' AS name, 'BD-UNION-3706' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Mohammadpur' AS name, 'BD-UNION-3707' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Bhognagar' AS name, 'BD-UNION-3708' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Sator' AS name, 'BD-UNION-3709' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Mohonpur' AS name, 'BD-UNION-3710' AS code
  UNION ALL
    SELECT 'BD-UPZ-405' AS parent_code, 'union' AS area_type, 'Moricha' AS name, 'BD-UNION-3711' AS code
  UNION ALL
    SELECT 'BD-UPZ-406' AS parent_code, 'union' AS area_type, 'Bulakipur' AS name, 'BD-UNION-3712' AS code
  UNION ALL
    SELECT 'BD-UPZ-406' AS parent_code, 'union' AS area_type, 'Palsha' AS name, 'BD-UNION-3713' AS code
  UNION ALL
    SELECT 'BD-UPZ-406' AS parent_code, 'union' AS area_type, 'Singra' AS name, 'BD-UNION-3714' AS code
  UNION ALL
    SELECT 'BD-UPZ-406' AS parent_code, 'union' AS area_type, 'Ghoraghat' AS name, 'BD-UNION-3715' AS code
  UNION ALL
    SELECT 'BD-UPZ-407' AS parent_code, 'union' AS area_type, 'Mukundopur' AS name, 'BD-UNION-3716' AS code
  UNION ALL
    SELECT 'BD-UPZ-407' AS parent_code, 'union' AS area_type, 'Katla' AS name, 'BD-UNION-3717' AS code
  UNION ALL
    SELECT 'BD-UPZ-407' AS parent_code, 'union' AS area_type, 'Khanpur' AS name, 'BD-UNION-3718' AS code
  UNION ALL
    SELECT 'BD-UPZ-407' AS parent_code, 'union' AS area_type, 'Dior' AS name, 'BD-UNION-3719' AS code
  UNION ALL
    SELECT 'BD-UPZ-407' AS parent_code, 'union' AS area_type, 'Binail' AS name, 'BD-UNION-3720' AS code
  UNION ALL
    SELECT 'BD-UPZ-407' AS parent_code, 'union' AS area_type, 'Jatbani' AS name, 'BD-UNION-3721' AS code
  UNION ALL
    SELECT 'BD-UPZ-407' AS parent_code, 'union' AS area_type, 'Poliproyagpur' AS name, 'BD-UNION-3722' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Belaichandi' AS name, 'BD-UNION-3723' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Monmothopur' AS name, 'BD-UNION-3724' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Rampur' AS name, 'BD-UNION-3725' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Polashbari' AS name, 'BD-UNION-3726' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Chandipur' AS name, 'BD-UNION-3727' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Mominpur' AS name, 'BD-UNION-3728' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Mostofapur' AS name, 'BD-UNION-3729' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Habra' AS name, 'BD-UNION-3730' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Hamidpur' AS name, 'BD-UNION-3731' AS code
  UNION ALL
    SELECT 'BD-UPZ-408' AS parent_code, 'union' AS area_type, 'Harirampur' AS name, 'BD-UNION-3732' AS code
  UNION ALL
    SELECT 'BD-UPZ-409' AS parent_code, 'union' AS area_type, 'Nafanagar' AS name, 'BD-UNION-3733' AS code
  UNION ALL
    SELECT 'BD-UPZ-409' AS parent_code, 'union' AS area_type, 'Eshania' AS name, 'BD-UNION-3734' AS code
  UNION ALL
    SELECT 'BD-UPZ-409' AS parent_code, 'union' AS area_type, 'Atgaon' AS name, 'BD-UNION-3735' AS code
  UNION ALL
    SELECT 'BD-UPZ-409' AS parent_code, 'union' AS area_type, 'Shatail' AS name, 'BD-UNION-3736' AS code
  UNION ALL
    SELECT 'BD-UPZ-409' AS parent_code, 'union' AS area_type, 'Rongaon' AS name, 'BD-UNION-3737' AS code
  UNION ALL
    SELECT 'BD-UPZ-409' AS parent_code, 'union' AS area_type, 'Murshidhat' AS name, 'BD-UNION-3738' AS code
  UNION ALL
    SELECT 'BD-UPZ-410' AS parent_code, 'union' AS area_type, 'Dabor' AS name, 'BD-UNION-3739' AS code
  UNION ALL
    SELECT 'BD-UPZ-410' AS parent_code, 'union' AS area_type, 'Rasulpur' AS name, 'BD-UNION-3740' AS code
  UNION ALL
    SELECT 'BD-UPZ-410' AS parent_code, 'union' AS area_type, 'Mukundapur' AS name, 'BD-UNION-3741' AS code
  UNION ALL
    SELECT 'BD-UPZ-410' AS parent_code, 'union' AS area_type, 'Targao' AS name, 'BD-UNION-3742' AS code
  UNION ALL
    SELECT 'BD-UPZ-410' AS parent_code, 'union' AS area_type, 'Ramchandrapur' AS name, 'BD-UNION-3743' AS code
  UNION ALL
    SELECT 'BD-UPZ-410' AS parent_code, 'union' AS area_type, 'Sundarpur' AS name, 'BD-UNION-3744' AS code
  UNION ALL
    SELECT 'BD-UPZ-411' AS parent_code, 'union' AS area_type, 'Aloary' AS name, 'BD-UNION-3745' AS code
  UNION ALL
    SELECT 'BD-UPZ-411' AS parent_code, 'union' AS area_type, 'Aladipur' AS name, 'BD-UNION-3746' AS code
  UNION ALL
    SELECT 'BD-UPZ-411' AS parent_code, 'union' AS area_type, 'Kagihal' AS name, 'BD-UNION-3747' AS code
  UNION ALL
    SELECT 'BD-UPZ-411' AS parent_code, 'union' AS area_type, 'Bethdighi' AS name, 'BD-UNION-3748' AS code
  UNION ALL
    SELECT 'BD-UPZ-411' AS parent_code, 'union' AS area_type, 'Khairbari' AS name, 'BD-UNION-3749' AS code
  UNION ALL
    SELECT 'BD-UPZ-411' AS parent_code, 'union' AS area_type, 'Daulatpur' AS name, 'BD-UNION-3750' AS code
  UNION ALL
    SELECT 'BD-UPZ-411' AS parent_code, 'union' AS area_type, 'Shibnagor' AS name, 'BD-UNION-3751' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Chealgazi' AS name, 'BD-UNION-3752' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Sundorbon' AS name, 'BD-UNION-3753' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Fazilpur' AS name, 'BD-UNION-3754' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Shekpura' AS name, 'BD-UNION-3755' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Shashora' AS name, 'BD-UNION-3756' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Auliapur' AS name, 'BD-UNION-3757' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Uthrail' AS name, 'BD-UNION-3758' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Sankarpur' AS name, 'BD-UNION-3759' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Askorpur' AS name, 'BD-UNION-3760' AS code
  UNION ALL
    SELECT 'BD-UPZ-412' AS parent_code, 'union' AS area_type, 'Kamalpur' AS name, 'BD-UNION-3761' AS code
  UNION ALL
    SELECT 'BD-UPZ-413' AS parent_code, 'union' AS area_type, 'Alihat' AS name, 'BD-UNION-3762' AS code
  UNION ALL
    SELECT 'BD-UPZ-413' AS parent_code, 'union' AS area_type, 'Khattamadobpara' AS name, 'BD-UNION-3763' AS code
  UNION ALL
    SELECT 'BD-UPZ-413' AS parent_code, 'union' AS area_type, 'Boalder' AS name, 'BD-UNION-3764' AS code
  UNION ALL
    SELECT 'BD-UPZ-414' AS parent_code, 'union' AS area_type, 'Alokjhari' AS name, 'BD-UNION-3765' AS code
  UNION ALL
    SELECT 'BD-UPZ-414' AS parent_code, 'union' AS area_type, 'Bherbheri' AS name, 'BD-UNION-3766' AS code
  UNION ALL
    SELECT 'BD-UPZ-414' AS parent_code, 'union' AS area_type, 'Angarpara' AS name, 'BD-UNION-3767' AS code
  UNION ALL
    SELECT 'BD-UPZ-414' AS parent_code, 'union' AS area_type, 'Goaldihi' AS name, 'BD-UNION-3768' AS code
  UNION ALL
    SELECT 'BD-UPZ-414' AS parent_code, 'union' AS area_type, 'Bhabki' AS name, 'BD-UNION-3769' AS code
  UNION ALL
    SELECT 'BD-UPZ-414' AS parent_code, 'union' AS area_type, 'Khamarpara' AS name, 'BD-UNION-3770' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Azimpur' AS name, 'BD-UNION-3771' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Farakkabad' AS name, 'BD-UNION-3772' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Dhamoir' AS name, 'BD-UNION-3773' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Shohorgram' AS name, 'BD-UNION-3774' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Birol' AS name, 'BD-UNION-3775' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Bhandra' AS name, 'BD-UNION-3776' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Bijora' AS name, 'BD-UNION-3777' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Dharmapur' AS name, 'BD-UNION-3778' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Mongalpur' AS name, 'BD-UNION-3779' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Ranipukur' AS name, 'BD-UNION-3780' AS code
  UNION ALL
    SELECT 'BD-UPZ-415' AS parent_code, 'union' AS area_type, 'Rajarampur' AS name, 'BD-UNION-3781' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Nashratpur' AS name, 'BD-UNION-3782' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Satnala' AS name, 'BD-UNION-3783' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Fatejangpur' AS name, 'BD-UNION-3784' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Isobpur' AS name, 'BD-UNION-3785' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Abdulpur' AS name, 'BD-UNION-3786' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Amarpur' AS name, 'BD-UNION-3787' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Auliapukur' AS name, 'BD-UNION-3788' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Saitara' AS name, 'BD-UNION-3789' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Viail' AS name, 'BD-UNION-3790' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Punotti' AS name, 'BD-UNION-3791' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Tetulia' AS name, 'BD-UNION-3792' AS code
  UNION ALL
    SELECT 'BD-UPZ-416' AS parent_code, 'union' AS area_type, 'Alokdihi' AS name, 'BD-UNION-3793' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Rajpur' AS name, 'BD-UNION-3794' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Harati' AS name, 'BD-UNION-3795' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Mogolhat' AS name, 'BD-UNION-3796' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Gokunda' AS name, 'BD-UNION-3797' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Barobari' AS name, 'BD-UNION-3798' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Kulaghat' AS name, 'BD-UNION-3799' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Mohendranagar' AS name, 'BD-UNION-3800' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Khuniagachh' AS name, 'BD-UNION-3801' AS code
  UNION ALL
    SELECT 'BD-UPZ-417' AS parent_code, 'union' AS area_type, 'Panchagram' AS name, 'BD-UNION-3802' AS code
  UNION ALL
    SELECT 'BD-UPZ-418' AS parent_code, 'union' AS area_type, 'Bhotmari' AS name, 'BD-UNION-3803' AS code
  UNION ALL
    SELECT 'BD-UPZ-418' AS parent_code, 'union' AS area_type, 'Modati' AS name, 'BD-UNION-3804' AS code
  UNION ALL
    SELECT 'BD-UPZ-418' AS parent_code, 'union' AS area_type, 'Dologram' AS name, 'BD-UNION-3805' AS code
  UNION ALL
    SELECT 'BD-UPZ-418' AS parent_code, 'union' AS area_type, 'Tushbhandar' AS name, 'BD-UNION-3806' AS code
  UNION ALL
    SELECT 'BD-UPZ-418' AS parent_code, 'union' AS area_type, 'Goral' AS name, 'BD-UNION-3807' AS code
  UNION ALL
    SELECT 'BD-UPZ-418' AS parent_code, 'union' AS area_type, 'Chondropur' AS name, 'BD-UNION-3808' AS code
  UNION ALL
    SELECT 'BD-UPZ-418' AS parent_code, 'union' AS area_type, 'Cholbola' AS name, 'BD-UNION-3809' AS code
  UNION ALL
    SELECT 'BD-UPZ-418' AS parent_code, 'union' AS area_type, 'Kakina' AS name, 'BD-UNION-3810' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Barokhata' AS name, 'BD-UNION-3811' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Goddimari' AS name, 'BD-UNION-3812' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Singimari' AS name, 'BD-UNION-3813' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Tongvhanga' AS name, 'BD-UNION-3814' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Sindurna' AS name, 'BD-UNION-3815' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Paticapara' AS name, 'BD-UNION-3816' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Nowdabas' AS name, 'BD-UNION-3817' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Gotamari' AS name, 'BD-UNION-3818' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Vhelaguri' AS name, 'BD-UNION-3819' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Shaniajan' AS name, 'BD-UNION-3820' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Fakirpara' AS name, 'BD-UNION-3821' AS code
  UNION ALL
    SELECT 'BD-UPZ-419' AS parent_code, 'union' AS area_type, 'Dawabari' AS name, 'BD-UNION-3822' AS code
  UNION ALL
    SELECT 'BD-UPZ-420' AS parent_code, 'union' AS area_type, 'Sreerampur' AS name, 'BD-UNION-3823' AS code
  UNION ALL
    SELECT 'BD-UPZ-420' AS parent_code, 'union' AS area_type, 'Patgram' AS name, 'BD-UNION-3824' AS code
  UNION ALL
    SELECT 'BD-UPZ-420' AS parent_code, 'union' AS area_type, 'Jagatber' AS name, 'BD-UNION-3825' AS code
  UNION ALL
    SELECT 'BD-UPZ-420' AS parent_code, 'union' AS area_type, 'Kuchlibari' AS name, 'BD-UNION-3826' AS code
  UNION ALL
    SELECT 'BD-UPZ-420' AS parent_code, 'union' AS area_type, 'Jongra' AS name, 'BD-UNION-3827' AS code
  UNION ALL
    SELECT 'BD-UPZ-420' AS parent_code, 'union' AS area_type, 'Baura' AS name, 'BD-UNION-3828' AS code
  UNION ALL
    SELECT 'BD-UPZ-420' AS parent_code, 'union' AS area_type, 'Dahagram' AS name, 'BD-UNION-3829' AS code
  UNION ALL
    SELECT 'BD-UPZ-420' AS parent_code, 'union' AS area_type, 'Burimari' AS name, 'BD-UNION-3830' AS code
  UNION ALL
    SELECT 'BD-UPZ-421' AS parent_code, 'union' AS area_type, 'Bhelabari' AS name, 'BD-UNION-3831' AS code
  UNION ALL
    SELECT 'BD-UPZ-421' AS parent_code, 'union' AS area_type, 'Bhadai' AS name, 'BD-UNION-3832' AS code
  UNION ALL
    SELECT 'BD-UPZ-421' AS parent_code, 'union' AS area_type, 'Kamlabari' AS name, 'BD-UNION-3833' AS code
  UNION ALL
    SELECT 'BD-UPZ-421' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-3834' AS code
  UNION ALL
    SELECT 'BD-UPZ-421' AS parent_code, 'union' AS area_type, 'Sarpukur' AS name, 'BD-UNION-3835' AS code
  UNION ALL
    SELECT 'BD-UPZ-421' AS parent_code, 'union' AS area_type, 'Saptibari' AS name, 'BD-UNION-3836' AS code
  UNION ALL
    SELECT 'BD-UPZ-421' AS parent_code, 'union' AS area_type, 'Palashi' AS name, 'BD-UNION-3837' AS code
  UNION ALL
    SELECT 'BD-UPZ-421' AS parent_code, 'union' AS area_type, 'Mohishkhocha' AS name, 'BD-UNION-3838' AS code
  UNION ALL
    SELECT 'BD-UPZ-422' AS parent_code, 'union' AS area_type, 'Kamarpukur' AS name, 'BD-UNION-3839' AS code
  UNION ALL
    SELECT 'BD-UPZ-422' AS parent_code, 'union' AS area_type, 'Kasiram Belpukur' AS name, 'BD-UNION-3840' AS code
  UNION ALL
    SELECT 'BD-UPZ-422' AS parent_code, 'union' AS area_type, 'Bangalipur' AS name, 'BD-UNION-3841' AS code
  UNION ALL
    SELECT 'BD-UPZ-422' AS parent_code, 'union' AS area_type, 'Botlagari' AS name, 'BD-UNION-3842' AS code
  UNION ALL
    SELECT 'BD-UPZ-422' AS parent_code, 'union' AS area_type, 'Khata Madhupur' AS name, 'BD-UNION-3843' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Gomnati' AS name, 'BD-UNION-3844' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Bhogdaburi' AS name, 'BD-UNION-3845' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Ketkibari' AS name, 'BD-UNION-3846' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Jorabari' AS name, 'BD-UNION-3847' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Bamunia' AS name, 'BD-UNION-3848' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Panga Motukpur' AS name, 'BD-UNION-3849' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Boragari' AS name, 'BD-UNION-3850' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Domar' AS name, 'BD-UNION-3851' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Sonaray' AS name, 'BD-UNION-3852' AS code
  UNION ALL
    SELECT 'BD-UPZ-423' AS parent_code, 'union' AS area_type, 'Harinchara' AS name, 'BD-UNION-3853' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Paschim Chhatnay' AS name, 'BD-UNION-3854' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Balapara' AS name, 'BD-UNION-3855' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Dimla Sadar' AS name, 'BD-UNION-3856' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Khogakharibari' AS name, 'BD-UNION-3857' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Gayabari' AS name, 'BD-UNION-3858' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Noutara' AS name, 'BD-UNION-3859' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Khalisha Chapani' AS name, 'BD-UNION-3860' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Jhunagach Chapani' AS name, 'BD-UNION-3861' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Tepa Khribari' AS name, 'BD-UNION-3862' AS code
  UNION ALL
    SELECT 'BD-UPZ-424' AS parent_code, 'union' AS area_type, 'Purba Chhatnay' AS name, 'BD-UNION-3863' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Douabari' AS name, 'BD-UNION-3864' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Golmunda' AS name, 'BD-UNION-3865' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Balagram' AS name, 'BD-UNION-3866' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Golna' AS name, 'BD-UNION-3867' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Dharmapal' AS name, 'BD-UNION-3868' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Simulbari' AS name, 'BD-UNION-3869' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Mirganj' AS name, 'BD-UNION-3870' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Kathali' AS name, 'BD-UNION-3871' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Khutamara' AS name, 'BD-UNION-3872' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Shaulmari' AS name, 'BD-UNION-3873' AS code
  UNION ALL
    SELECT 'BD-UPZ-425' AS parent_code, 'union' AS area_type, 'Kaimari' AS name, 'BD-UNION-3874' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Barabhita' AS name, 'BD-UNION-3875' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Putimari' AS name, 'BD-UNION-3876' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Nitai' AS name, 'BD-UNION-3877' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Bahagili' AS name, 'BD-UNION-3878' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Chandkhana' AS name, 'BD-UNION-3879' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Kishoreganj' AS name, 'BD-UNION-3880' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Ranachandi' AS name, 'BD-UNION-3881' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Garagram' AS name, 'BD-UNION-3882' AS code
  UNION ALL
    SELECT 'BD-UPZ-426' AS parent_code, 'union' AS area_type, 'Magura' AS name, 'BD-UNION-3883' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Chaora Bargacha' AS name, 'BD-UNION-3884' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Gorgram' AS name, 'BD-UNION-3885' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Khoksabari' AS name, 'BD-UNION-3886' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Palasbari' AS name, 'BD-UNION-3887' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Ramnagar' AS name, 'BD-UNION-3888' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Kachukata' AS name, 'BD-UNION-3889' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Panchapukur' AS name, 'BD-UNION-3890' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Itakhola' AS name, 'BD-UNION-3891' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Kundapukur' AS name, 'BD-UNION-3892' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Sonaray' AS name, 'BD-UNION-3893' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Songalsi' AS name, 'BD-UNION-3894' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Charaikhola' AS name, 'BD-UNION-3895' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Chapra Sarnjami' AS name, 'BD-UNION-3896' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Lakshmicha' AS name, 'BD-UNION-3897' AS code
  UNION ALL
    SELECT 'BD-UPZ-427' AS parent_code, 'union' AS area_type, 'Tupamari' AS name, 'BD-UNION-3898' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Rasulpur' AS name, 'BD-UNION-3899' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Noldanga' AS name, 'BD-UNION-3900' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Damodorpur' AS name, 'BD-UNION-3901' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Jamalpur' AS name, 'BD-UNION-3902' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Faridpur' AS name, 'BD-UNION-3903' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Dhaperhat' AS name, 'BD-UNION-3904' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Idilpur' AS name, 'BD-UNION-3905' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Vatgram' AS name, 'BD-UNION-3906' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Bongram' AS name, 'BD-UNION-3907' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Kamarpara' AS name, 'BD-UNION-3908' AS code
  UNION ALL
    SELECT 'BD-UPZ-428' AS parent_code, 'union' AS area_type, 'Khodkomor' AS name, 'BD-UNION-3909' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Laxmipur' AS name, 'BD-UNION-3910' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Malibari' AS name, 'BD-UNION-3911' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Kuptola' AS name, 'BD-UNION-3912' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Shahapara' AS name, 'BD-UNION-3913' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Ballamjhar' AS name, 'BD-UNION-3914' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Ramchandrapur' AS name, 'BD-UNION-3915' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Badiakhali' AS name, 'BD-UNION-3916' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Boali' AS name, 'BD-UNION-3917' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Ghagoa' AS name, 'BD-UNION-3918' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Gidari' AS name, 'BD-UNION-3919' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Kholahati' AS name, 'BD-UNION-3920' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Mollarchar' AS name, 'BD-UNION-3921' AS code
  UNION ALL
    SELECT 'BD-UPZ-429' AS parent_code, 'union' AS area_type, 'Kamarjani' AS name, 'BD-UNION-3922' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Kishoregari' AS name, 'BD-UNION-3923' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Hosenpur' AS name, 'BD-UNION-3924' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Palashbari' AS name, 'BD-UNION-3925' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Barisal' AS name, 'BD-UNION-3926' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Mohdipur' AS name, 'BD-UNION-3927' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Betkapa' AS name, 'BD-UNION-3928' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Pobnapur' AS name, 'BD-UNION-3929' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Monohorpur' AS name, 'BD-UNION-3930' AS code
  UNION ALL
    SELECT 'BD-UPZ-430' AS parent_code, 'union' AS area_type, 'Harinathpur' AS name, 'BD-UNION-3931' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Padumsahar' AS name, 'BD-UNION-3932' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Varotkhali' AS name, 'BD-UNION-3933' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Saghata' AS name, 'BD-UNION-3934' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Muktinagar' AS name, 'BD-UNION-3935' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Kachua' AS name, 'BD-UNION-3936' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Ghuridah' AS name, 'BD-UNION-3937' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Holdia' AS name, 'BD-UNION-3938' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Jumarbari' AS name, 'BD-UNION-3939' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Kamalerpara' AS name, 'BD-UNION-3940' AS code
  UNION ALL
    SELECT 'BD-UPZ-431' AS parent_code, 'union' AS area_type, 'Bonarpara' AS name, 'BD-UNION-3941' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Kamdia' AS name, 'BD-UNION-3942' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Katabari' AS name, 'BD-UNION-3943' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Shakhahar' AS name, 'BD-UNION-3944' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Rajahar' AS name, 'BD-UNION-3945' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Sapmara' AS name, 'BD-UNION-3946' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Dorbosto' AS name, 'BD-UNION-3947' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Talukkanupur' AS name, 'BD-UNION-3948' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Nakai' AS name, 'BD-UNION-3949' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Harirampur' AS name, 'BD-UNION-3950' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Rakhalburuj' AS name, 'BD-UNION-3951' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Phulbari' AS name, 'BD-UNION-3952' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Gumaniganj' AS name, 'BD-UNION-3953' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Kamardoho' AS name, 'BD-UNION-3954' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Kochasahar' AS name, 'BD-UNION-3955' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Shibpur' AS name, 'BD-UNION-3956' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Mahimaganj' AS name, 'BD-UNION-3957' AS code
  UNION ALL
    SELECT 'BD-UPZ-432' AS parent_code, 'union' AS area_type, 'Shalmara' AS name, 'BD-UNION-3958' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Bamondanga' AS name, 'BD-UNION-3959' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Sonaroy' AS name, 'BD-UNION-3960' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Tarapur' AS name, 'BD-UNION-3961' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Belka' AS name, 'BD-UNION-3962' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Dohbond' AS name, 'BD-UNION-3963' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Sorbanondo' AS name, 'BD-UNION-3964' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Ramjibon' AS name, 'BD-UNION-3965' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Dhopadanga' AS name, 'BD-UNION-3966' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Chaporhati' AS name, 'BD-UNION-3967' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Shantiram' AS name, 'BD-UNION-3968' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Konchibari' AS name, 'BD-UNION-3969' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Sreepur' AS name, 'BD-UNION-3970' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Chandipur' AS name, 'BD-UNION-3971' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Kapasia' AS name, 'BD-UNION-3972' AS code
  UNION ALL
    SELECT 'BD-UPZ-433' AS parent_code, 'union' AS area_type, 'Haripur' AS name, 'BD-UNION-3973' AS code
  UNION ALL
    SELECT 'BD-UPZ-434' AS parent_code, 'union' AS area_type, 'Kanchipara' AS name, 'BD-UNION-3974' AS code
  UNION ALL
    SELECT 'BD-UPZ-434' AS parent_code, 'union' AS area_type, 'Uria' AS name, 'BD-UNION-3975' AS code
  UNION ALL
    SELECT 'BD-UPZ-434' AS parent_code, 'union' AS area_type, 'Udakhali' AS name, 'BD-UNION-3976' AS code
  UNION ALL
    SELECT 'BD-UPZ-434' AS parent_code, 'union' AS area_type, 'Gazaria' AS name, 'BD-UNION-3977' AS code
  UNION ALL
    SELECT 'BD-UPZ-434' AS parent_code, 'union' AS area_type, 'Phulchari' AS name, 'BD-UNION-3978' AS code
  UNION ALL
    SELECT 'BD-UPZ-434' AS parent_code, 'union' AS area_type, 'Erendabari' AS name, 'BD-UNION-3979' AS code
  UNION ALL
    SELECT 'BD-UPZ-434' AS parent_code, 'union' AS area_type, 'Fazlupur' AS name, 'BD-UNION-3980' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Ruhea' AS name, 'BD-UNION-3981' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Akhanagar' AS name, 'BD-UNION-3982' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Ahcha' AS name, 'BD-UNION-3983' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Baragaon' AS name, 'BD-UNION-3984' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Balia' AS name, 'BD-UNION-3985' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Auliapur' AS name, 'BD-UNION-3986' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Chilarang' AS name, 'BD-UNION-3987' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Rahimanpur' AS name, 'BD-UNION-3988' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Roypur' AS name, 'BD-UNION-3989' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Jamalpur' AS name, 'BD-UNION-3990' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Mohammadpur' AS name, 'BD-UNION-3991' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Salandar' AS name, 'BD-UNION-3992' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Gareya' AS name, 'BD-UNION-3993' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Rajagaon' AS name, 'BD-UNION-3994' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Debipur' AS name, 'BD-UNION-3995' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Nargun' AS name, 'BD-UNION-3996' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Jagannathpur' AS name, 'BD-UNION-3997' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Sukhanpukhari' AS name, 'BD-UNION-3998' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Begunbari' AS name, 'BD-UNION-3999' AS code
  UNION ALL
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Ruhia Pashchim' AS name, 'BD-UNION-4000' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;