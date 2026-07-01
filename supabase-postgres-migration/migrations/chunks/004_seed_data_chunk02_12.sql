INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-435' AS parent_code, 'union' AS area_type, 'Dholarhat' AS name, 'BD-UNION-4001' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Bhomradaha' AS name, 'BD-UNION-4002' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Kosharaniganj' AS name, 'BD-UNION-4003' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Khangaon' AS name, 'BD-UNION-4004' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Saidpur' AS name, 'BD-UNION-4005' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Pirganj' AS name, 'BD-UNION-4006' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Hajipur' AS name, 'BD-UNION-4007' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Daulatpur' AS name, 'BD-UNION-4008' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Sengaon' AS name, 'BD-UNION-4009' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Jabarhat' AS name, 'BD-UNION-4010' AS code
  UNION ALL
    SELECT 'BD-UPZ-436' AS parent_code, 'union' AS area_type, 'Bairchuna' AS name, 'BD-UNION-4011' AS code
  UNION ALL
    SELECT 'BD-UPZ-437' AS parent_code, 'union' AS area_type, 'Dhormogarh' AS name, 'BD-UNION-4012' AS code
  UNION ALL
    SELECT 'BD-UPZ-437' AS parent_code, 'union' AS area_type, 'Nekmorod' AS name, 'BD-UNION-4013' AS code
  UNION ALL
    SELECT 'BD-UPZ-437' AS parent_code, 'union' AS area_type, 'Hosengaon' AS name, 'BD-UNION-4014' AS code
  UNION ALL
    SELECT 'BD-UPZ-437' AS parent_code, 'union' AS area_type, 'Lehemba' AS name, 'BD-UNION-4015' AS code
  UNION ALL
    SELECT 'BD-UPZ-437' AS parent_code, 'union' AS area_type, 'Bachor' AS name, 'BD-UNION-4016' AS code
  UNION ALL
    SELECT 'BD-UPZ-437' AS parent_code, 'union' AS area_type, 'Kashipur' AS name, 'BD-UNION-4017' AS code
  UNION ALL
    SELECT 'BD-UPZ-437' AS parent_code, 'union' AS area_type, 'Ratore' AS name, 'BD-UNION-4018' AS code
  UNION ALL
    SELECT 'BD-UPZ-437' AS parent_code, 'union' AS area_type, 'Nonduar' AS name, 'BD-UNION-4019' AS code
  UNION ALL
    SELECT 'BD-UPZ-438' AS parent_code, 'union' AS area_type, 'Gedura' AS name, 'BD-UNION-4020' AS code
  UNION ALL
    SELECT 'BD-UPZ-438' AS parent_code, 'union' AS area_type, 'Amgaon' AS name, 'BD-UNION-4021' AS code
  UNION ALL
    SELECT 'BD-UPZ-438' AS parent_code, 'union' AS area_type, 'Bakua' AS name, 'BD-UNION-4022' AS code
  UNION ALL
    SELECT 'BD-UPZ-438' AS parent_code, 'union' AS area_type, 'Dangipara' AS name, 'BD-UNION-4023' AS code
  UNION ALL
    SELECT 'BD-UPZ-438' AS parent_code, 'union' AS area_type, 'Haripur' AS name, 'BD-UNION-4024' AS code
  UNION ALL
    SELECT 'BD-UPZ-438' AS parent_code, 'union' AS area_type, 'Bhaturia' AS name, 'BD-UNION-4025' AS code
  UNION ALL
    SELECT 'BD-UPZ-439' AS parent_code, 'union' AS area_type, 'Paria' AS name, 'BD-UNION-4026' AS code
  UNION ALL
    SELECT 'BD-UPZ-439' AS parent_code, 'union' AS area_type, 'Charol' AS name, 'BD-UNION-4027' AS code
  UNION ALL
    SELECT 'BD-UPZ-439' AS parent_code, 'union' AS area_type, 'Dhontola' AS name, 'BD-UNION-4028' AS code
  UNION ALL
    SELECT 'BD-UPZ-439' AS parent_code, 'union' AS area_type, 'Boropalashbari' AS name, 'BD-UNION-4029' AS code
  UNION ALL
    SELECT 'BD-UPZ-439' AS parent_code, 'union' AS area_type, 'Duosuo' AS name, 'BD-UNION-4030' AS code
  UNION ALL
    SELECT 'BD-UPZ-439' AS parent_code, 'union' AS area_type, 'Vanor' AS name, 'BD-UNION-4031' AS code
  UNION ALL
    SELECT 'BD-UPZ-439' AS parent_code, 'union' AS area_type, 'Amjankhore' AS name, 'BD-UNION-4032' AS code
  UNION ALL
    SELECT 'BD-UPZ-439' AS parent_code, 'union' AS area_type, 'Borobari' AS name, 'BD-UNION-4033' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Mominpur' AS name, 'BD-UNION-4034' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Horidebpur' AS name, 'BD-UNION-4035' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Uttam' AS name, 'BD-UNION-4036' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Porshuram' AS name, 'BD-UNION-4037' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Topodhan' AS name, 'BD-UNION-4038' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Satgara' AS name, 'BD-UNION-4039' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Rajendrapur' AS name, 'BD-UNION-4040' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Sadwapuskoroni' AS name, 'BD-UNION-4041' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Chandanpat' AS name, 'BD-UNION-4042' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Dorshona' AS name, 'BD-UNION-4043' AS code
  UNION ALL
    SELECT 'BD-UPZ-440' AS parent_code, 'union' AS area_type, 'Tampat' AS name, 'BD-UNION-4044' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Betgari' AS name, 'BD-UNION-4045' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Kholeya' AS name, 'BD-UNION-4046' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Borobil' AS name, 'BD-UNION-4047' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Kolcondo' AS name, 'BD-UNION-4048' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Gongachora' AS name, 'BD-UNION-4049' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Gojoghonta' AS name, 'BD-UNION-4050' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Morneya' AS name, 'BD-UNION-4051' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Alambiditor' AS name, 'BD-UNION-4052' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Lakkhitari' AS name, 'BD-UNION-4053' AS code
  UNION ALL
    SELECT 'BD-UPZ-441' AS parent_code, 'union' AS area_type, 'Nohali' AS name, 'BD-UNION-4054' AS code
  UNION ALL
    SELECT 'BD-UPZ-442' AS parent_code, 'union' AS area_type, 'Kurshatara' AS name, 'BD-UNION-4055' AS code
  UNION ALL
    SELECT 'BD-UPZ-442' AS parent_code, 'union' AS area_type, 'Alampur' AS name, 'BD-UNION-4056' AS code
  UNION ALL
    SELECT 'BD-UPZ-442' AS parent_code, 'union' AS area_type, 'Soyar' AS name, 'BD-UNION-4057' AS code
  UNION ALL
    SELECT 'BD-UPZ-442' AS parent_code, 'union' AS area_type, 'Ikorchali' AS name, 'BD-UNION-4058' AS code
  UNION ALL
    SELECT 'BD-UPZ-442' AS parent_code, 'union' AS area_type, 'Hariarkuthi' AS name, 'BD-UNION-4059' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Radhanagar' AS name, 'BD-UNION-4060' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Gopinathpur' AS name, 'BD-UNION-4061' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Modhupur' AS name, 'BD-UNION-4062' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Kutubpur' AS name, 'BD-UNION-4063' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Bishnapur' AS name, 'BD-UNION-4064' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Kalupara' AS name, 'BD-UNION-4065' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Lohanipara' AS name, 'BD-UNION-4066' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Gopalpur' AS name, 'BD-UNION-4067' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Damodorpur' AS name, 'BD-UNION-4068' AS code
  UNION ALL
    SELECT 'BD-UPZ-443' AS parent_code, 'union' AS area_type, 'Ramnathpurupb' AS name, 'BD-UNION-4069' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Khoragach' AS name, 'BD-UNION-4070' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Ranipukur' AS name, 'BD-UNION-4071' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Payrabond' AS name, 'BD-UNION-4072' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Vangni' AS name, 'BD-UNION-4073' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Balarhat' AS name, 'BD-UNION-4074' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Kafrikhal' AS name, 'BD-UNION-4075' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Latibpur' AS name, 'BD-UNION-4076' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Chengmari' AS name, 'BD-UNION-4077' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Moyenpur' AS name, 'BD-UNION-4078' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Baluya Masimpur' AS name, 'BD-UNION-4079' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Borobala' AS name, 'BD-UNION-4080' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Mirzapur' AS name, 'BD-UNION-4081' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Imadpur' AS name, 'BD-UNION-4082' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Milonpur' AS name, 'BD-UNION-4083' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Mgopalpur' AS name, 'BD-UNION-4084' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-4085' AS code
  UNION ALL
    SELECT 'BD-UPZ-444' AS parent_code, 'union' AS area_type, 'Boro Hazratpur' AS name, 'BD-UNION-4086' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Chattracol' AS name, 'BD-UNION-4087' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Vendabari' AS name, 'BD-UNION-4088' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Borodargah' AS name, 'BD-UNION-4089' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Kumedpur' AS name, 'BD-UNION-4090' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Modankhali' AS name, 'BD-UNION-4091' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Tukuria' AS name, 'BD-UNION-4092' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Boro Alampur' AS name, 'BD-UNION-4093' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Raypur' AS name, 'BD-UNION-4094' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Pirgonj' AS name, 'BD-UNION-4095' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Shanerhat' AS name, 'BD-UNION-4096' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Mithipur' AS name, 'BD-UNION-4097' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Ramnathpur' AS name, 'BD-UNION-4098' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Chattra' AS name, 'BD-UNION-4099' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Kabilpur' AS name, 'BD-UNION-4100' AS code
  UNION ALL
    SELECT 'BD-UPZ-445' AS parent_code, 'union' AS area_type, 'Pachgachi' AS name, 'BD-UNION-4101' AS code
  UNION ALL
    SELECT 'BD-UPZ-446' AS parent_code, 'union' AS area_type, 'Sarai' AS name, 'BD-UNION-4102' AS code
  UNION ALL
    SELECT 'BD-UPZ-446' AS parent_code, 'union' AS area_type, 'Balapara' AS name, 'BD-UNION-4103' AS code
  UNION ALL
    SELECT 'BD-UPZ-446' AS parent_code, 'union' AS area_type, 'Shahidbag' AS name, 'BD-UNION-4104' AS code
  UNION ALL
    SELECT 'BD-UPZ-446' AS parent_code, 'union' AS area_type, 'Haragach' AS name, 'BD-UNION-4105' AS code
  UNION ALL
    SELECT 'BD-UPZ-446' AS parent_code, 'union' AS area_type, 'Tepamodhupur' AS name, 'BD-UNION-4106' AS code
  UNION ALL
    SELECT 'BD-UPZ-446' AS parent_code, 'union' AS area_type, 'Kurshaupk' AS name, 'BD-UNION-4107' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Kollyani' AS name, 'BD-UNION-4108' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Parul' AS name, 'BD-UNION-4109' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Itakumari' AS name, 'BD-UNION-4110' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Saula' AS name, 'BD-UNION-4111' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Kandi' AS name, 'BD-UNION-4112' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Pirgacha' AS name, 'BD-UNION-4113' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Annodanagar' AS name, 'BD-UNION-4114' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Tambulpur' AS name, 'BD-UNION-4115' AS code
  UNION ALL
    SELECT 'BD-UPZ-447' AS parent_code, 'union' AS area_type, 'Koikuri' AS name, 'BD-UNION-4116' AS code
  UNION ALL
    SELECT 'BD-UPZ-448' AS parent_code, 'union' AS area_type, 'Holokhana' AS name, 'BD-UNION-4117' AS code
  UNION ALL
    SELECT 'BD-UPZ-448' AS parent_code, 'union' AS area_type, 'Ghogadhoh' AS name, 'BD-UNION-4118' AS code
  UNION ALL
    SELECT 'BD-UPZ-448' AS parent_code, 'union' AS area_type, 'Belgacha' AS name, 'BD-UNION-4119' AS code
  UNION ALL
    SELECT 'BD-UPZ-448' AS parent_code, 'union' AS area_type, 'Mogolbasa' AS name, 'BD-UNION-4120' AS code
  UNION ALL
    SELECT 'BD-UPZ-448' AS parent_code, 'union' AS area_type, 'Panchgachi' AS name, 'BD-UNION-4121' AS code
  UNION ALL
    SELECT 'BD-UPZ-448' AS parent_code, 'union' AS area_type, 'Jatrapur' AS name, 'BD-UNION-4122' AS code
  UNION ALL
    SELECT 'BD-UPZ-448' AS parent_code, 'union' AS area_type, 'Kanthalbari' AS name, 'BD-UNION-4123' AS code
  UNION ALL
    SELECT 'BD-UPZ-448' AS parent_code, 'union' AS area_type, 'Bhogdanga' AS name, 'BD-UNION-4124' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Ramkhana' AS name, 'BD-UNION-4125' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Raigonj' AS name, 'BD-UNION-4126' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Bamondanga' AS name, 'BD-UNION-4127' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Berubari' AS name, 'BD-UNION-4128' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Sontaspur' AS name, 'BD-UNION-4129' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Hasnabad' AS name, 'BD-UNION-4130' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Newyashi' AS name, 'BD-UNION-4131' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Bhitorbond' AS name, 'BD-UNION-4132' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Kaligonj' AS name, 'BD-UNION-4133' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Noonkhawa' AS name, 'BD-UNION-4134' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Narayanpur' AS name, 'BD-UNION-4135' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Kedar' AS name, 'BD-UNION-4136' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Kachakata' AS name, 'BD-UNION-4137' AS code
  UNION ALL
    SELECT 'BD-UPZ-449' AS parent_code, 'union' AS area_type, 'Bollobherkhas' AS name, 'BD-UNION-4138' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Pathordubi' AS name, 'BD-UNION-4139' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Shilkhuri' AS name, 'BD-UNION-4140' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Tilai' AS name, 'BD-UNION-4141' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Paikarchara' AS name, 'BD-UNION-4142' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Bhurungamari' AS name, 'BD-UNION-4143' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Joymonirhat' AS name, 'BD-UNION-4144' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Andharirjhar' AS name, 'BD-UNION-4145' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Char-Bhurungamari' AS name, 'BD-UNION-4146' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Bangasonahat' AS name, 'BD-UNION-4147' AS code
  UNION ALL
    SELECT 'BD-UPZ-450' AS parent_code, 'union' AS area_type, 'Boldia' AS name, 'BD-UNION-4148' AS code
  UNION ALL
    SELECT 'BD-UPZ-451' AS parent_code, 'union' AS area_type, 'Nawdanga' AS name, 'BD-UNION-4149' AS code
  UNION ALL
    SELECT 'BD-UPZ-451' AS parent_code, 'union' AS area_type, 'Shimulbari' AS name, 'BD-UNION-4150' AS code
  UNION ALL
    SELECT 'BD-UPZ-451' AS parent_code, 'union' AS area_type, 'Phulbari' AS name, 'BD-UNION-4151' AS code
  UNION ALL
    SELECT 'BD-UPZ-451' AS parent_code, 'union' AS area_type, 'Baravita' AS name, 'BD-UNION-4152' AS code
  UNION ALL
    SELECT 'BD-UPZ-451' AS parent_code, 'union' AS area_type, 'Bhangamor' AS name, 'BD-UNION-4153' AS code
  UNION ALL
    SELECT 'BD-UPZ-451' AS parent_code, 'union' AS area_type, 'Kashipur' AS name, 'BD-UNION-4154' AS code
  UNION ALL
    SELECT 'BD-UPZ-452' AS parent_code, 'union' AS area_type, 'Chinai' AS name, 'BD-UNION-4155' AS code
  UNION ALL
    SELECT 'BD-UPZ-452' AS parent_code, 'union' AS area_type, 'Rajarhat' AS name, 'BD-UNION-4156' AS code
  UNION ALL
    SELECT 'BD-UPZ-452' AS parent_code, 'union' AS area_type, 'Nazimkhan' AS name, 'BD-UNION-4157' AS code
  UNION ALL
    SELECT 'BD-UPZ-452' AS parent_code, 'union' AS area_type, 'Gharialdanga' AS name, 'BD-UNION-4158' AS code
  UNION ALL
    SELECT 'BD-UPZ-452' AS parent_code, 'union' AS area_type, 'Chakirpashar' AS name, 'BD-UNION-4159' AS code
  UNION ALL
    SELECT 'BD-UPZ-452' AS parent_code, 'union' AS area_type, 'Biddanondo' AS name, 'BD-UNION-4160' AS code
  UNION ALL
    SELECT 'BD-UPZ-452' AS parent_code, 'union' AS area_type, 'Umarmajid' AS name, 'BD-UNION-4161' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Daldalia' AS name, 'BD-UNION-4162' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-4163' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Pandul' AS name, 'BD-UNION-4164' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Buraburi' AS name, 'BD-UNION-4165' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Dharanibari' AS name, 'BD-UNION-4166' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Dhamsreni' AS name, 'BD-UNION-4167' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Gunaigas' AS name, 'BD-UNION-4168' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Bazra' AS name, 'BD-UNION-4169' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Tobockpur' AS name, 'BD-UNION-4170' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Hatia' AS name, 'BD-UNION-4171' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Begumgonj' AS name, 'BD-UNION-4172' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Shahabiar Alga' AS name, 'BD-UNION-4173' AS code
  UNION ALL
    SELECT 'BD-UPZ-453' AS parent_code, 'union' AS area_type, 'Thetrai' AS name, 'BD-UNION-4174' AS code
  UNION ALL
    SELECT 'BD-UPZ-454' AS parent_code, 'union' AS area_type, 'Ranigonj' AS name, 'BD-UNION-4175' AS code
  UNION ALL
    SELECT 'BD-UPZ-454' AS parent_code, 'union' AS area_type, 'Nayarhat' AS name, 'BD-UNION-4176' AS code
  UNION ALL
    SELECT 'BD-UPZ-454' AS parent_code, 'union' AS area_type, 'Thanahat' AS name, 'BD-UNION-4177' AS code
  UNION ALL
    SELECT 'BD-UPZ-454' AS parent_code, 'union' AS area_type, 'Ramna' AS name, 'BD-UNION-4178' AS code
  UNION ALL
    SELECT 'BD-UPZ-454' AS parent_code, 'union' AS area_type, 'Chilmari' AS name, 'BD-UNION-4179' AS code
  UNION ALL
    SELECT 'BD-UPZ-454' AS parent_code, 'union' AS area_type, 'Austomirchar' AS name, 'BD-UNION-4180' AS code
  UNION ALL
    SELECT 'BD-UPZ-455' AS parent_code, 'union' AS area_type, 'Dadevanga' AS name, 'BD-UNION-4181' AS code
  UNION ALL
    SELECT 'BD-UPZ-455' AS parent_code, 'union' AS area_type, 'Shoulemari' AS name, 'BD-UNION-4182' AS code
  UNION ALL
    SELECT 'BD-UPZ-455' AS parent_code, 'union' AS area_type, 'Bondober' AS name, 'BD-UNION-4183' AS code
  UNION ALL
    SELECT 'BD-UPZ-455' AS parent_code, 'union' AS area_type, 'Rowmari' AS name, 'BD-UNION-4184' AS code
  UNION ALL
    SELECT 'BD-UPZ-455' AS parent_code, 'union' AS area_type, 'Jadurchar' AS name, 'BD-UNION-4185' AS code
  UNION ALL
    SELECT 'BD-UPZ-456' AS parent_code, 'union' AS area_type, 'Rajibpur' AS name, 'BD-UNION-4186' AS code
  UNION ALL
    SELECT 'BD-UPZ-456' AS parent_code, 'union' AS area_type, 'Kodalkati' AS name, 'BD-UNION-4187' AS code
  UNION ALL
    SELECT 'BD-UPZ-456' AS parent_code, 'union' AS area_type, 'Mohongonj' AS name, 'BD-UNION-4188' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Kamararchor' AS name, 'BD-UNION-4189' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Chorsherpur' AS name, 'BD-UNION-4190' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Bajitkhila' AS name, 'BD-UNION-4191' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Gajir Khamar' AS name, 'BD-UNION-4192' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Dhola' AS name, 'BD-UNION-4193' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Pakuriya' AS name, 'BD-UNION-4194' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Vatshala' AS name, 'BD-UNION-4195' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Losmonpur' AS name, 'BD-UNION-4196' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Rouha' AS name, 'BD-UNION-4197' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Kamariya' AS name, 'BD-UNION-4198' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Chor Mochoriya' AS name, 'BD-UNION-4199' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Chorpokhimari' AS name, 'BD-UNION-4200' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Betmari Ghughurakandi' AS name, 'BD-UNION-4201' AS code
  UNION ALL
    SELECT 'BD-UPZ-457' AS parent_code, 'union' AS area_type, 'Balairchar' AS name, 'BD-UNION-4202' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Puraga' AS name, 'BD-UNION-4203' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Nonni' AS name, 'BD-UNION-4204' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Morichpuran' AS name, 'BD-UNION-4205' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Rajnogor' AS name, 'BD-UNION-4206' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Nayabil' AS name, 'BD-UNION-4207' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Ramchondrokura' AS name, 'BD-UNION-4208' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Kakorkandhi' AS name, 'BD-UNION-4209' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Nalitabari' AS name, 'BD-UNION-4210' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Juganiya' AS name, 'BD-UNION-4211' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Bagber' AS name, 'BD-UNION-4212' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Koloshpar' AS name, 'BD-UNION-4213' AS code
  UNION ALL
    SELECT 'BD-UPZ-458' AS parent_code, 'union' AS area_type, 'Rupnarayankura' AS name, 'BD-UNION-4214' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Ranishimul' AS name, 'BD-UNION-4215' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Singabaruna' AS name, 'BD-UNION-4216' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Kakilakura' AS name, 'BD-UNION-4217' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Tatihati' AS name, 'BD-UNION-4218' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Gosaipur' AS name, 'BD-UNION-4219' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Sreebordi' AS name, 'BD-UNION-4220' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Bhelua' AS name, 'BD-UNION-4221' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Kharia Kazirchar' AS name, 'BD-UNION-4222' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Kurikahonia' AS name, 'BD-UNION-4223' AS code
  UNION ALL
    SELECT 'BD-UPZ-459' AS parent_code, 'union' AS area_type, 'Garjaripa' AS name, 'BD-UNION-4224' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Gonopoddi' AS name, 'BD-UNION-4225' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Nokla' AS name, 'BD-UNION-4226' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Urpha' AS name, 'BD-UNION-4227' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Gourdwar' AS name, 'BD-UNION-4228' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Baneshwardi' AS name, 'BD-UNION-4229' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Pathakata' AS name, 'BD-UNION-4230' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Talki' AS name, 'BD-UNION-4231' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Choraustadhar' AS name, 'BD-UNION-4232' AS code
  UNION ALL
    SELECT 'BD-UPZ-460' AS parent_code, 'union' AS area_type, 'Chandrakona' AS name, 'BD-UNION-4233' AS code
  UNION ALL
    SELECT 'BD-UPZ-461' AS parent_code, 'union' AS area_type, 'Kansa' AS name, 'BD-UNION-4234' AS code
  UNION ALL
    SELECT 'BD-UPZ-461' AS parent_code, 'union' AS area_type, 'Dansail' AS name, 'BD-UNION-4235' AS code
  UNION ALL
    SELECT 'BD-UPZ-461' AS parent_code, 'union' AS area_type, 'Nolkura' AS name, 'BD-UNION-4236' AS code
  UNION ALL
    SELECT 'BD-UPZ-461' AS parent_code, 'union' AS area_type, 'Gouripur' AS name, 'BD-UNION-4237' AS code
  UNION ALL
    SELECT 'BD-UPZ-461' AS parent_code, 'union' AS area_type, 'Jhenaigati' AS name, 'BD-UNION-4238' AS code
  UNION ALL
    SELECT 'BD-UPZ-461' AS parent_code, 'union' AS area_type, 'Hatibandha' AS name, 'BD-UNION-4239' AS code
  UNION ALL
    SELECT 'BD-UPZ-461' AS parent_code, 'union' AS area_type, 'Malijhikanda' AS name, 'BD-UNION-4240' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Deukhola' AS name, 'BD-UNION-4241' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Naogaon' AS name, 'BD-UNION-4242' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Putijana' AS name, 'BD-UNION-4243' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Kushmail' AS name, 'BD-UNION-4244' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Fulbaria' AS name, 'BD-UNION-4245' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Bakta' AS name, 'BD-UNION-4246' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Rangamatia' AS name, 'BD-UNION-4247' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Enayetpur' AS name, 'BD-UNION-4248' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Kaladaha' AS name, 'BD-UNION-4249' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Radhakanai' AS name, 'BD-UNION-4250' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Asimpatuli' AS name, 'BD-UNION-4251' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Vobanipur' AS name, 'BD-UNION-4252' AS code
  UNION ALL
    SELECT 'BD-UPZ-462' AS parent_code, 'union' AS area_type, 'Balian' AS name, 'BD-UNION-4253' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Dhanikhola' AS name, 'BD-UNION-4254' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Bailor' AS name, 'BD-UNION-4255' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Kanthal' AS name, 'BD-UNION-4256' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Kanihari' AS name, 'BD-UNION-4257' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Trishal' AS name, 'BD-UNION-4258' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Harirampur' AS name, 'BD-UNION-4259' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Sakhua' AS name, 'BD-UNION-4260' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Balipara' AS name, 'BD-UNION-4261' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Mokshapur' AS name, 'BD-UNION-4262' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Mathbari' AS name, 'BD-UNION-4263' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Amirabari' AS name, 'BD-UNION-4264' AS code
  UNION ALL
    SELECT 'BD-UPZ-463' AS parent_code, 'union' AS area_type, 'Rampur' AS name, 'BD-UNION-4265' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Uthura' AS name, 'BD-UNION-4266' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Meduari' AS name, 'BD-UNION-4267' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Varadoba' AS name, 'BD-UNION-4268' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Dhitpur' AS name, 'BD-UNION-4269' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Dakatia' AS name, 'BD-UNION-4270' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Birunia' AS name, 'BD-UNION-4271' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Bhaluka' AS name, 'BD-UNION-4272' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Mallikbari' AS name, 'BD-UNION-4273' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Kachina' AS name, 'BD-UNION-4274' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Habirbari' AS name, 'BD-UNION-4275' AS code
  UNION ALL
    SELECT 'BD-UPZ-464' AS parent_code, 'union' AS area_type, 'Rajoi' AS name, 'BD-UNION-4276' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Dulla' AS name, 'BD-UNION-4277' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Borogram' AS name, 'BD-UNION-4278' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Tarati' AS name, 'BD-UNION-4279' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Kumargata' AS name, 'BD-UNION-4280' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Basati' AS name, 'BD-UNION-4281' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Mankon' AS name, 'BD-UNION-4282' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Ghoga' AS name, 'BD-UNION-4283' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Daogaon' AS name, 'BD-UNION-4284' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Kashimpur' AS name, 'BD-UNION-4285' AS code
  UNION ALL
    SELECT 'BD-UPZ-465' AS parent_code, 'union' AS area_type, 'Kheruajani' AS name, 'BD-UNION-4286' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Austadhar' AS name, 'BD-UNION-4287' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Bororchar' AS name, 'BD-UNION-4288' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Dapunia' AS name, 'BD-UNION-4289' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Aqua' AS name, 'BD-UNION-4290' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Khagdohor' AS name, 'BD-UNION-4291' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Charnilaxmia' AS name, 'BD-UNION-4292' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Kushtia' AS name, 'BD-UNION-4293' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Paranganj' AS name, 'BD-UNION-4294' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Sirta' AS name, 'BD-UNION-4295' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Char Ishwardia' AS name, 'BD-UNION-4296' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Ghagra' AS name, 'BD-UNION-4297' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Vabokhali' AS name, 'BD-UNION-4298' AS code
  UNION ALL
    SELECT 'BD-UPZ-466' AS parent_code, 'union' AS area_type, 'Boyra' AS name, 'BD-UNION-4299' AS code
  UNION ALL
    SELECT 'BD-UPZ-467' AS parent_code, 'union' AS area_type, 'Dakshin Maijpara' AS name, 'BD-UNION-4300' AS code
  UNION ALL
    SELECT 'BD-UPZ-467' AS parent_code, 'union' AS area_type, 'Gamaritola' AS name, 'BD-UNION-4301' AS code
  UNION ALL
    SELECT 'BD-UPZ-467' AS parent_code, 'union' AS area_type, 'Dhobaura' AS name, 'BD-UNION-4302' AS code
  UNION ALL
    SELECT 'BD-UPZ-467' AS parent_code, 'union' AS area_type, 'Porakandulia' AS name, 'BD-UNION-4303' AS code
  UNION ALL
    SELECT 'BD-UPZ-467' AS parent_code, 'union' AS area_type, 'Goatala' AS name, 'BD-UNION-4304' AS code
  UNION ALL
    SELECT 'BD-UPZ-467' AS parent_code, 'union' AS area_type, 'Ghoshgaon' AS name, 'BD-UNION-4305' AS code
  UNION ALL
    SELECT 'BD-UPZ-467' AS parent_code, 'union' AS area_type, 'Baghber' AS name, 'BD-UNION-4306' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Rambhadrapur' AS name, 'BD-UNION-4307' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Sondhara' AS name, 'BD-UNION-4308' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Vaitkandi' AS name, 'BD-UNION-4309' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Singheshwar' AS name, 'BD-UNION-4310' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Phulpur' AS name, 'BD-UNION-4311' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Banihala' AS name, 'BD-UNION-4312' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Biska' AS name, 'BD-UNION-4313' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Baola' AS name, 'BD-UNION-4314' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Payari' AS name, 'BD-UNION-4315' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Balia' AS name, 'BD-UNION-4316' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Rahimganj' AS name, 'BD-UNION-4317' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Balikha' AS name, 'BD-UNION-4318' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Kakni' AS name, 'BD-UNION-4319' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Dhakua' AS name, 'BD-UNION-4320' AS code
  UNION ALL
    SELECT 'BD-UPZ-468' AS parent_code, 'union' AS area_type, 'Rupasi' AS name, 'BD-UNION-4321' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Tarakanda' AS name, 'BD-UNION-4322' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Galagaon' AS name, 'BD-UNION-4323' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Kamargaon' AS name, 'BD-UNION-4324' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Kamaria' AS name, 'BD-UNION-4325' AS code
  UNION ALL
    SELECT 'BD-UPZ-474' AS parent_code, 'union' AS area_type, 'Rampur' AS name, 'BD-UNION-4326' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Bhubankura' AS name, 'BD-UNION-4327' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Jugli' AS name, 'BD-UNION-4328' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Kaichapur' AS name, 'BD-UNION-4329' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Haluaghat' AS name, 'BD-UNION-4330' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Gazirbhita' AS name, 'BD-UNION-4331' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Bildora' AS name, 'BD-UNION-4332' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Sakuai' AS name, 'BD-UNION-4333' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Narail' AS name, 'BD-UNION-4334' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Dhara' AS name, 'BD-UNION-4335' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Dhurail' AS name, 'BD-UNION-4336' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Amtoil' AS name, 'BD-UNION-4337' AS code
  UNION ALL
    SELECT 'BD-UPZ-469' AS parent_code, 'union' AS area_type, 'Swadeshi' AS name, 'BD-UNION-4338' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Sahanati' AS name, 'BD-UNION-4339' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Achintapur' AS name, 'BD-UNION-4340' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Mailakanda' AS name, 'BD-UNION-4341' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Bokainagar' AS name, 'BD-UNION-4342' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Gouripur' AS name, 'BD-UNION-4343' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Maoha' AS name, 'BD-UNION-4344' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Ramgopalpur' AS name, 'BD-UNION-4345' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Douhakhola' AS name, 'BD-UNION-4346' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Bhangnamari' AS name, 'BD-UNION-4347' AS code
  UNION ALL
    SELECT 'BD-UPZ-470' AS parent_code, 'union' AS area_type, 'Sidhla' AS name, 'BD-UNION-4348' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Rasulpur' AS name, 'BD-UNION-4349' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Barobaria' AS name, 'BD-UNION-4350' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Charalgi' AS name, 'BD-UNION-4351' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Saltia' AS name, 'BD-UNION-4352' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Raona' AS name, 'BD-UNION-4353' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Longair' AS name, 'BD-UNION-4354' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Paithol' AS name, 'BD-UNION-4355' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Gafargaon' AS name, 'BD-UNION-4356' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Josora' AS name, 'BD-UNION-4357' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Moshakhali' AS name, 'BD-UNION-4358' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Panchbagh' AS name, 'BD-UNION-4359' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Usthi' AS name, 'BD-UNION-4360' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Dotterbazar' AS name, 'BD-UNION-4361' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Niguari' AS name, 'BD-UNION-4362' AS code
  UNION ALL
    SELECT 'BD-UPZ-471' AS parent_code, 'union' AS area_type, 'Tangabo' AS name, 'BD-UNION-4363' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Iswarganj' AS name, 'BD-UNION-4364' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Sarisha' AS name, 'BD-UNION-4365' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Sohagi' AS name, 'BD-UNION-4366' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Atharabari' AS name, 'BD-UNION-4367' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Rajibpur' AS name, 'BD-UNION-4368' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Maijbagh' AS name, 'BD-UNION-4369' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Magtula' AS name, 'BD-UNION-4370' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Jatia' AS name, 'BD-UNION-4371' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Uchakhila' AS name, 'BD-UNION-4372' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Tarundia' AS name, 'BD-UNION-4373' AS code
  UNION ALL
    SELECT 'BD-UPZ-472' AS parent_code, 'union' AS area_type, 'Barahit' AS name, 'BD-UNION-4374' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Batagoir' AS name, 'BD-UNION-4375' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Nandail' AS name, 'BD-UNION-4376' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Chandipasha' AS name, 'BD-UNION-4377' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Gangail' AS name, 'BD-UNION-4378' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Rajgati' AS name, 'BD-UNION-4379' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Muajjempur' AS name, 'BD-UNION-4380' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Sherpur' AS name, 'BD-UNION-4381' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Singroil' AS name, 'BD-UNION-4382' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Achargaon' AS name, 'BD-UNION-4383' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Mushulli' AS name, 'BD-UNION-4384' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Kharua' AS name, 'BD-UNION-4385' AS code
  UNION ALL
    SELECT 'BD-UPZ-473' AS parent_code, 'union' AS area_type, 'Jahangirpur' AS name, 'BD-UNION-4386' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Kendua' AS name, 'BD-UNION-4387' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Sharifpur' AS name, 'BD-UNION-4388' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Laxirchar' AS name, 'BD-UNION-4389' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Tolshirchar' AS name, 'BD-UNION-4390' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Itail' AS name, 'BD-UNION-4391' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Narundi' AS name, 'BD-UNION-4392' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Ghorada' AS name, 'BD-UNION-4393' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Bashchara' AS name, 'BD-UNION-4394' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Ranagacha' AS name, 'BD-UNION-4395' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Sheepur' AS name, 'BD-UNION-4396' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Shahbajpur' AS name, 'BD-UNION-4397' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Titpalla' AS name, 'BD-UNION-4398' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Mesta' AS name, 'BD-UNION-4399' AS code
  UNION ALL
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Digpait' AS name, 'BD-UNION-4400' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;

INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-475' AS parent_code, 'union' AS area_type, 'Rashidpur' AS name, 'BD-UNION-4401' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Durmot' AS name, 'BD-UNION-4402' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Kulia' AS name, 'BD-UNION-4403' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Mahmudpur' AS name, 'BD-UNION-4404' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Nangla' AS name, 'BD-UNION-4405' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Nayanagar' AS name, 'BD-UNION-4406' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Adra' AS name, 'BD-UNION-4407' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Charbani Pakuria' AS name, 'BD-UNION-4408' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Fulkucha' AS name, 'BD-UNION-4409' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Ghuserpara' AS name, 'BD-UNION-4410' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Jhaugara' AS name, 'BD-UNION-4411' AS code
  UNION ALL
    SELECT 'BD-UPZ-476' AS parent_code, 'union' AS area_type, 'Shuampur' AS name, 'BD-UNION-4412' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Kulkandi' AS name, 'BD-UNION-4413' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Belghacha' AS name, 'BD-UNION-4414' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Chinaduli' AS name, 'BD-UNION-4415' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Shapdari' AS name, 'BD-UNION-4416' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Noarpara' AS name, 'BD-UNION-4417' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Islampur' AS name, 'BD-UNION-4418' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Partharshi' AS name, 'BD-UNION-4419' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Palabandha' AS name, 'BD-UNION-4420' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Gualerchar' AS name, 'BD-UNION-4421' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Gaibandha' AS name, 'BD-UNION-4422' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Charputimari' AS name, 'BD-UNION-4423' AS code
  UNION ALL
    SELECT 'BD-UPZ-477' AS parent_code, 'union' AS area_type, 'Chargualini' AS name, 'BD-UNION-4424' AS code
  UNION ALL
    SELECT 'BD-UPZ-478' AS parent_code, 'union' AS area_type, 'Dungdhara' AS name, 'BD-UNION-4425' AS code
  UNION ALL
    SELECT 'BD-UPZ-478' AS parent_code, 'union' AS area_type, 'Char Amkhawa' AS name, 'BD-UNION-4426' AS code
  UNION ALL
    SELECT 'BD-UPZ-478' AS parent_code, 'union' AS area_type, 'Parram Rampur' AS name, 'BD-UNION-4427' AS code
  UNION ALL
    SELECT 'BD-UPZ-478' AS parent_code, 'union' AS area_type, 'Hatibanga' AS name, 'BD-UNION-4428' AS code
  UNION ALL
    SELECT 'BD-UPZ-478' AS parent_code, 'union' AS area_type, 'Bahadurabad' AS name, 'BD-UNION-4429' AS code
  UNION ALL
    SELECT 'BD-UPZ-478' AS parent_code, 'union' AS area_type, 'Chikajani' AS name, 'BD-UNION-4430' AS code
  UNION ALL
    SELECT 'BD-UPZ-478' AS parent_code, 'union' AS area_type, 'Chukaibari' AS name, 'BD-UNION-4431' AS code
  UNION ALL
    SELECT 'BD-UPZ-478' AS parent_code, 'union' AS area_type, 'Dewangonj' AS name, 'BD-UNION-4432' AS code
  UNION ALL
    SELECT 'BD-UPZ-479' AS parent_code, 'union' AS area_type, 'Satpoa' AS name, 'BD-UNION-4433' AS code
  UNION ALL
    SELECT 'BD-UPZ-479' AS parent_code, 'union' AS area_type, 'Pogaldigha' AS name, 'BD-UNION-4434' AS code
  UNION ALL
    SELECT 'BD-UPZ-479' AS parent_code, 'union' AS area_type, 'Doail' AS name, 'BD-UNION-4435' AS code
  UNION ALL
    SELECT 'BD-UPZ-479' AS parent_code, 'union' AS area_type, 'Aona' AS name, 'BD-UNION-4436' AS code
  UNION ALL
    SELECT 'BD-UPZ-479' AS parent_code, 'union' AS area_type, 'Pingna' AS name, 'BD-UNION-4437' AS code
  UNION ALL
    SELECT 'BD-UPZ-479' AS parent_code, 'union' AS area_type, 'Bhatara' AS name, 'BD-UNION-4438' AS code
  UNION ALL
    SELECT 'BD-UPZ-479' AS parent_code, 'union' AS area_type, 'Kamrabad' AS name, 'BD-UNION-4439' AS code
  UNION ALL
    SELECT 'BD-UPZ-479' AS parent_code, 'union' AS area_type, 'Mahadan' AS name, 'BD-UNION-4440' AS code
  UNION ALL
    SELECT 'BD-UPZ-480' AS parent_code, 'union' AS area_type, 'Char Pakerdah' AS name, 'BD-UNION-4441' AS code
  UNION ALL
    SELECT 'BD-UPZ-480' AS parent_code, 'union' AS area_type, 'Karaichara' AS name, 'BD-UNION-4442' AS code
  UNION ALL
    SELECT 'BD-UPZ-480' AS parent_code, 'union' AS area_type, 'Gunaritala' AS name, 'BD-UNION-4443' AS code
  UNION ALL
    SELECT 'BD-UPZ-480' AS parent_code, 'union' AS area_type, 'Balijuri' AS name, 'BD-UNION-4444' AS code
  UNION ALL
    SELECT 'BD-UPZ-480' AS parent_code, 'union' AS area_type, 'Jorekhali' AS name, 'BD-UNION-4445' AS code
  UNION ALL
    SELECT 'BD-UPZ-480' AS parent_code, 'union' AS area_type, 'Adarvita' AS name, 'BD-UNION-4446' AS code
  UNION ALL
    SELECT 'BD-UPZ-480' AS parent_code, 'union' AS area_type, 'Sidhuli' AS name, 'BD-UNION-4447' AS code
  UNION ALL
    SELECT 'BD-UPZ-481' AS parent_code, 'union' AS area_type, 'Danua' AS name, 'BD-UNION-4448' AS code
  UNION ALL
    SELECT 'BD-UPZ-481' AS parent_code, 'union' AS area_type, 'Bagarchar' AS name, 'BD-UNION-4449' AS code
  UNION ALL
    SELECT 'BD-UPZ-481' AS parent_code, 'union' AS area_type, 'Battajore' AS name, 'BD-UNION-4450' AS code
  UNION ALL
    SELECT 'BD-UPZ-481' AS parent_code, 'union' AS area_type, 'Shadurpara' AS name, 'BD-UNION-4451' AS code
  UNION ALL
    SELECT 'BD-UPZ-481' AS parent_code, 'union' AS area_type, 'Bakshigonj' AS name, 'BD-UNION-4452' AS code
  UNION ALL
    SELECT 'BD-UPZ-481' AS parent_code, 'union' AS area_type, 'Nilakhia' AS name, 'BD-UNION-4453' AS code
  UNION ALL
    SELECT 'BD-UPZ-481' AS parent_code, 'union' AS area_type, 'Merurchar' AS name, 'BD-UNION-4454' AS code
  UNION ALL
    SELECT 'BD-UPZ-482' AS parent_code, 'union' AS area_type, 'Asma' AS name, 'BD-UNION-4455' AS code
  UNION ALL
    SELECT 'BD-UPZ-482' AS parent_code, 'union' AS area_type, 'Chhiram' AS name, 'BD-UNION-4456' AS code
  UNION ALL
    SELECT 'BD-UPZ-482' AS parent_code, 'union' AS area_type, 'Baushi' AS name, 'BD-UNION-4457' AS code
  UNION ALL
    SELECT 'BD-UPZ-482' AS parent_code, 'union' AS area_type, 'Barhatta' AS name, 'BD-UNION-4458' AS code
  UNION ALL
    SELECT 'BD-UPZ-482' AS parent_code, 'union' AS area_type, 'Raypur' AS name, 'BD-UNION-4459' AS code
  UNION ALL
    SELECT 'BD-UPZ-482' AS parent_code, 'union' AS area_type, 'Sahata' AS name, 'BD-UNION-4460' AS code
  UNION ALL
    SELECT 'BD-UPZ-482' AS parent_code, 'union' AS area_type, 'Singdha' AS name, 'BD-UNION-4461' AS code
  UNION ALL
    SELECT 'BD-UPZ-483' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-4462' AS code
  UNION ALL
    SELECT 'BD-UPZ-483' AS parent_code, 'union' AS area_type, 'Kakoirgora' AS name, 'BD-UNION-4463' AS code
  UNION ALL
    SELECT 'BD-UPZ-483' AS parent_code, 'union' AS area_type, 'Kullagora' AS name, 'BD-UNION-4464' AS code
  UNION ALL
    SELECT 'BD-UPZ-483' AS parent_code, 'union' AS area_type, 'Chandigarh' AS name, 'BD-UNION-4465' AS code
  UNION ALL
    SELECT 'BD-UPZ-483' AS parent_code, 'union' AS area_type, 'Birisiri' AS name, 'BD-UNION-4466' AS code
  UNION ALL
    SELECT 'BD-UPZ-483' AS parent_code, 'union' AS area_type, 'Bakaljora' AS name, 'BD-UNION-4467' AS code
  UNION ALL
    SELECT 'BD-UPZ-483' AS parent_code, 'union' AS area_type, 'Gawkandia' AS name, 'BD-UNION-4468' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Asujia' AS name, 'BD-UNION-4469' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Dalpa' AS name, 'BD-UNION-4470' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Goraduba' AS name, 'BD-UNION-4471' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Gonda' AS name, 'BD-UNION-4472' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Sandikona' AS name, 'BD-UNION-4473' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Maska' AS name, 'BD-UNION-4474' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Bolaishimul' AS name, 'BD-UNION-4475' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Noapara' AS name, 'BD-UNION-4476' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Kandiura' AS name, 'BD-UNION-4477' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Chirang' AS name, 'BD-UNION-4478' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Roailbari Amtala' AS name, 'BD-UNION-4479' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Paikura' AS name, 'BD-UNION-4480' AS code
  UNION ALL
    SELECT 'BD-UPZ-484' AS parent_code, 'union' AS area_type, 'Muzafarpur' AS name, 'BD-UNION-4481' AS code
  UNION ALL
    SELECT 'BD-UPZ-485' AS parent_code, 'union' AS area_type, 'Shormushia' AS name, 'BD-UNION-4482' AS code
  UNION ALL
    SELECT 'BD-UPZ-485' AS parent_code, 'union' AS area_type, 'Shunoi' AS name, 'BD-UNION-4483' AS code
  UNION ALL
    SELECT 'BD-UPZ-485' AS parent_code, 'union' AS area_type, 'Lunesshor' AS name, 'BD-UNION-4484' AS code
  UNION ALL
    SELECT 'BD-UPZ-485' AS parent_code, 'union' AS area_type, 'Baniyajan' AS name, 'BD-UNION-4485' AS code
  UNION ALL
    SELECT 'BD-UPZ-485' AS parent_code, 'union' AS area_type, 'Teligati' AS name, 'BD-UNION-4486' AS code
  UNION ALL
    SELECT 'BD-UPZ-485' AS parent_code, 'union' AS area_type, 'Duoj' AS name, 'BD-UNION-4487' AS code
  UNION ALL
    SELECT 'BD-UPZ-485' AS parent_code, 'union' AS area_type, 'Sukhari' AS name, 'BD-UNION-4488' AS code
  UNION ALL
    SELECT 'BD-UPZ-486' AS parent_code, 'union' AS area_type, 'Fathepur' AS name, 'BD-UNION-4489' AS code
  UNION ALL
    SELECT 'BD-UPZ-486' AS parent_code, 'union' AS area_type, 'Nayekpur' AS name, 'BD-UNION-4490' AS code
  UNION ALL
    SELECT 'BD-UPZ-486' AS parent_code, 'union' AS area_type, 'Teosree' AS name, 'BD-UNION-4491' AS code
  UNION ALL
    SELECT 'BD-UPZ-486' AS parent_code, 'union' AS area_type, 'Magan' AS name, 'BD-UNION-4492' AS code
  UNION ALL
    SELECT 'BD-UPZ-486' AS parent_code, 'union' AS area_type, 'Gobindasree' AS name, 'BD-UNION-4493' AS code
  UNION ALL
    SELECT 'BD-UPZ-486' AS parent_code, 'union' AS area_type, 'Madan' AS name, 'BD-UNION-4494' AS code
  UNION ALL
    SELECT 'BD-UPZ-486' AS parent_code, 'union' AS area_type, 'Chandgaw' AS name, 'BD-UNION-4495' AS code
  UNION ALL
    SELECT 'BD-UPZ-486' AS parent_code, 'union' AS area_type, 'Kytail' AS name, 'BD-UNION-4496' AS code
  UNION ALL
    SELECT 'BD-UPZ-487' AS parent_code, 'union' AS area_type, 'Krishnapur' AS name, 'BD-UNION-4497' AS code
  UNION ALL
    SELECT 'BD-UPZ-487' AS parent_code, 'union' AS area_type, 'Nogor' AS name, 'BD-UNION-4498' AS code
  UNION ALL
    SELECT 'BD-UPZ-487' AS parent_code, 'union' AS area_type, 'Chakua' AS name, 'BD-UNION-4499' AS code
  UNION ALL
    SELECT 'BD-UPZ-487' AS parent_code, 'union' AS area_type, 'Khaliajuri' AS name, 'BD-UNION-4500' AS code
  UNION ALL
    SELECT 'BD-UPZ-487' AS parent_code, 'union' AS area_type, 'Mendipur' AS name, 'BD-UNION-4501' AS code
  UNION ALL
    SELECT 'BD-UPZ-487' AS parent_code, 'union' AS area_type, 'Gazipur' AS name, 'BD-UNION-4502' AS code
  UNION ALL
    SELECT 'BD-UPZ-488' AS parent_code, 'union' AS area_type, 'Koilati' AS name, 'BD-UNION-4503' AS code
  UNION ALL
    SELECT 'BD-UPZ-488' AS parent_code, 'union' AS area_type, 'Najirpur' AS name, 'BD-UNION-4504' AS code
  UNION ALL
    SELECT 'BD-UPZ-488' AS parent_code, 'union' AS area_type, 'Pogla' AS name, 'BD-UNION-4505' AS code
  UNION ALL
    SELECT 'BD-UPZ-488' AS parent_code, 'union' AS area_type, 'Kolmakanda' AS name, 'BD-UNION-4506' AS code
  UNION ALL
    SELECT 'BD-UPZ-488' AS parent_code, 'union' AS area_type, 'Rongchati' AS name, 'BD-UNION-4507' AS code
  UNION ALL
    SELECT 'BD-UPZ-488' AS parent_code, 'union' AS area_type, 'Lengura' AS name, 'BD-UNION-4508' AS code
  UNION ALL
    SELECT 'BD-UPZ-488' AS parent_code, 'union' AS area_type, 'Borokhapon' AS name, 'BD-UNION-4509' AS code
  UNION ALL
    SELECT 'BD-UPZ-488' AS parent_code, 'union' AS area_type, 'Kharnoi' AS name, 'BD-UNION-4510' AS code
  UNION ALL
    SELECT 'BD-UPZ-489' AS parent_code, 'union' AS area_type, 'Borokashia Birampur' AS name, 'BD-UNION-4511' AS code
  UNION ALL
    SELECT 'BD-UPZ-489' AS parent_code, 'union' AS area_type, 'Borotoli Banihari' AS name, 'BD-UNION-4512' AS code
  UNION ALL
    SELECT 'BD-UPZ-489' AS parent_code, 'union' AS area_type, 'Tetulia' AS name, 'BD-UNION-4513' AS code
  UNION ALL
    SELECT 'BD-UPZ-489' AS parent_code, 'union' AS area_type, 'Maghan Siadar' AS name, 'BD-UNION-4514' AS code
  UNION ALL
    SELECT 'BD-UPZ-489' AS parent_code, 'union' AS area_type, 'Somaj Sohildeo' AS name, 'BD-UNION-4515' AS code
  UNION ALL
    SELECT 'BD-UPZ-489' AS parent_code, 'union' AS area_type, 'Suair' AS name, 'BD-UNION-4516' AS code
  UNION ALL
    SELECT 'BD-UPZ-489' AS parent_code, 'union' AS area_type, 'Gaglajur' AS name, 'BD-UNION-4517' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Khalishaur' AS name, 'BD-UNION-4518' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Ghagra' AS name, 'BD-UNION-4519' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Jaria' AS name, 'BD-UNION-4520' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Narandia' AS name, 'BD-UNION-4521' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Bishkakuni' AS name, 'BD-UNION-4522' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Bairaty' AS name, 'BD-UNION-4523' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Hogla' AS name, 'BD-UNION-4524' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Gohalakanda' AS name, 'BD-UNION-4525' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Dhalamulgaon' AS name, 'BD-UNION-4526' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Agia' AS name, 'BD-UNION-4527' AS code
  UNION ALL
    SELECT 'BD-UPZ-490' AS parent_code, 'union' AS area_type, 'Purbadhala' AS name, 'BD-UNION-4528' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Chollisha' AS name, 'BD-UNION-4529' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Kailati' AS name, 'BD-UNION-4530' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Dokkhin Bishiura' AS name, 'BD-UNION-4531' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Modonpur' AS name, 'BD-UNION-4532' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Amtola' AS name, 'BD-UNION-4533' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Lokkhiganj' AS name, 'BD-UNION-4534' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Singher Bangla' AS name, 'BD-UNION-4535' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Thakurakona' AS name, 'BD-UNION-4536' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Mougati' AS name, 'BD-UNION-4537' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Rouha' AS name, 'BD-UNION-4538' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Medni' AS name, 'BD-UNION-4539' AS code
  UNION ALL
    SELECT 'BD-UPZ-491' AS parent_code, 'union' AS area_type, 'Kaliara Babragati' AS name, 'BD-UNION-4540' AS code

) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;