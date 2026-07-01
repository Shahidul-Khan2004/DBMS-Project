INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Purbagujra' AS name, 'BD-UNION-801' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Paschim Gujra' AS name, 'BD-UNION-802' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Gohira' AS name, 'BD-UNION-803' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Holdia' AS name, 'BD-UNION-804' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Kodolpur' AS name, 'BD-UNION-805' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Noapara' AS name, 'BD-UNION-806' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Pahartali' AS name, 'BD-UNION-807' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Urkirchar' AS name, 'BD-UNION-808' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Nowajushpur' AS name, 'BD-UNION-809' AS code
  UNION ALL
    SELECT 'BD-UPZ-79' AS parent_code, 'union' AS area_type, 'Char Patharghata' AS name, 'BD-UNION-810' AS code
  UNION ALL
    SELECT 'BD-UPZ-79' AS parent_code, 'union' AS area_type, 'Char Lakshya' AS name, 'BD-UNION-811' AS code
  UNION ALL
    SELECT 'BD-UPZ-79' AS parent_code, 'union' AS area_type, 'Juldha' AS name, 'BD-UNION-812' AS code
  UNION ALL
    SELECT 'BD-UPZ-79' AS parent_code, 'union' AS area_type, 'Barauthan' AS name, 'BD-UNION-813' AS code
  UNION ALL
    SELECT 'BD-UPZ-79' AS parent_code, 'union' AS area_type, 'Sikalbaha' AS name, 'BD-UNION-814' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Islamabad' AS name, 'BD-UNION-815' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Islampur' AS name, 'BD-UNION-816' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Pokkhali' AS name, 'BD-UNION-817' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Eidgaon' AS name, 'BD-UNION-818' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Jalalabad' AS name, 'BD-UNION-819' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Chowfaldandi' AS name, 'BD-UNION-820' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Varuakhali' AS name, 'BD-UNION-821' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Pmkhali' AS name, 'BD-UNION-822' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Khurushkhul' AS name, 'BD-UNION-823' AS code
  UNION ALL
    SELECT 'BD-UPZ-80' AS parent_code, 'union' AS area_type, 'Jhilongjha' AS name, 'BD-UNION-824' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Kakhara' AS name, 'BD-UNION-825' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Kaiar Bil' AS name, 'BD-UNION-826' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Konakhali' AS name, 'BD-UNION-827' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Khuntakhali' AS name, 'BD-UNION-828' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Chiringa' AS name, 'BD-UNION-829' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Demusia' AS name, 'BD-UNION-830' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Dulahazara' AS name, 'BD-UNION-831' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Paschim Bara Bheola' AS name, 'BD-UNION-832' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Badarkhali' AS name, 'BD-UNION-833' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Bamobil Chari' AS name, 'BD-UNION-834' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Baraitali' AS name, 'BD-UNION-835' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Bheola Manik Char' AS name, 'BD-UNION-836' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Saharbil' AS name, 'BD-UNION-837' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Surajpur Manikpur' AS name, 'BD-UNION-838' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Harbang' AS name, 'BD-UNION-839' AS code
  UNION ALL
    SELECT 'BD-UPZ-81' AS parent_code, 'union' AS area_type, 'Fashiakhali' AS name, 'BD-UNION-840' AS code
  UNION ALL
    SELECT 'BD-UPZ-82' AS parent_code, 'union' AS area_type, 'Ali Akbar Deil' AS name, 'BD-UNION-841' AS code
  UNION ALL
    SELECT 'BD-UPZ-82' AS parent_code, 'union' AS area_type, 'Uttar Dhurung' AS name, 'BD-UNION-842' AS code
  UNION ALL
    SELECT 'BD-UPZ-82' AS parent_code, 'union' AS area_type, 'Kaiyarbil' AS name, 'BD-UNION-843' AS code
  UNION ALL
    SELECT 'BD-UPZ-82' AS parent_code, 'union' AS area_type, 'Dakshi Dhurung' AS name, 'BD-UNION-844' AS code
  UNION ALL
    SELECT 'BD-UPZ-82' AS parent_code, 'union' AS area_type, 'Baragho' AS name, 'BD-UNION-845' AS code
  UNION ALL
    SELECT 'BD-UPZ-82' AS parent_code, 'union' AS area_type, 'Lemsikhali' AS name, 'BD-UNION-846' AS code
  UNION ALL
    SELECT 'BD-UPZ-83' AS parent_code, 'union' AS area_type, 'Rajapalong' AS name, 'BD-UNION-847' AS code
  UNION ALL
    SELECT 'BD-UPZ-83' AS parent_code, 'union' AS area_type, 'Jaliapalong' AS name, 'BD-UNION-848' AS code
  UNION ALL
    SELECT 'BD-UPZ-83' AS parent_code, 'union' AS area_type, 'Holdiapalong' AS name, 'BD-UNION-849' AS code
  UNION ALL
    SELECT 'BD-UPZ-83' AS parent_code, 'union' AS area_type, 'Ratnapalong' AS name, 'BD-UNION-850' AS code
  UNION ALL
    SELECT 'BD-UPZ-83' AS parent_code, 'union' AS area_type, 'Palongkhali' AS name, 'BD-UNION-851' AS code
  UNION ALL
    SELECT 'BD-UPZ-84' AS parent_code, 'union' AS area_type, 'Boro Moheshkhali' AS name, 'BD-UNION-852' AS code
  UNION ALL
    SELECT 'BD-UPZ-84' AS parent_code, 'union' AS area_type, 'Choto Moheshkhali' AS name, 'BD-UNION-853' AS code
  UNION ALL
    SELECT 'BD-UPZ-84' AS parent_code, 'union' AS area_type, 'Shaplapur' AS name, 'BD-UNION-854' AS code
  UNION ALL
    SELECT 'BD-UPZ-84' AS parent_code, 'union' AS area_type, 'Kutubjum' AS name, 'BD-UNION-855' AS code
  UNION ALL
    SELECT 'BD-UPZ-84' AS parent_code, 'union' AS area_type, 'Hoanak' AS name, 'BD-UNION-856' AS code
  UNION ALL
    SELECT 'BD-UPZ-84' AS parent_code, 'union' AS area_type, 'Kalarmarchhara' AS name, 'BD-UNION-857' AS code
  UNION ALL
    SELECT 'BD-UPZ-84' AS parent_code, 'union' AS area_type, 'Matarbari' AS name, 'BD-UNION-858' AS code
  UNION ALL
    SELECT 'BD-UPZ-84' AS parent_code, 'union' AS area_type, 'Dhalghata' AS name, 'BD-UNION-859' AS code
  UNION ALL
    SELECT 'BD-UPZ-85' AS parent_code, 'union' AS area_type, 'Ujantia' AS name, 'BD-UNION-860' AS code
  UNION ALL
    SELECT 'BD-UPZ-85' AS parent_code, 'union' AS area_type, 'Taitong' AS name, 'BD-UNION-861' AS code
  UNION ALL
    SELECT 'BD-UPZ-85' AS parent_code, 'union' AS area_type, 'Pekua' AS name, 'BD-UNION-862' AS code
  UNION ALL
    SELECT 'BD-UPZ-85' AS parent_code, 'union' AS area_type, 'Barabakia' AS name, 'BD-UNION-863' AS code
  UNION ALL
    SELECT 'BD-UPZ-85' AS parent_code, 'union' AS area_type, 'Magnama' AS name, 'BD-UNION-864' AS code
  UNION ALL
    SELECT 'BD-UPZ-85' AS parent_code, 'union' AS area_type, 'Rajakhali' AS name, 'BD-UNION-865' AS code
  UNION ALL
    SELECT 'BD-UPZ-85' AS parent_code, 'union' AS area_type, 'Shilkhali' AS name, 'BD-UNION-866' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Fotekharkul' AS name, 'BD-UNION-867' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Rajarkul' AS name, 'BD-UNION-868' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Rashidnagar' AS name, 'BD-UNION-869' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Khuniapalong' AS name, 'BD-UNION-870' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Eidghar' AS name, 'BD-UNION-871' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Chakmarkul' AS name, 'BD-UNION-872' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Kacchapia' AS name, 'BD-UNION-873' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Kauwarkho' AS name, 'BD-UNION-874' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Dakkhin Mithachhari' AS name, 'BD-UNION-875' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Jouarianala' AS name, 'BD-UNION-876' AS code
  UNION ALL
    SELECT 'BD-UPZ-86' AS parent_code, 'union' AS area_type, 'Garjoniya' AS name, 'BD-UNION-877' AS code
  UNION ALL
    SELECT 'BD-UPZ-87' AS parent_code, 'union' AS area_type, 'Subrang' AS name, 'BD-UNION-878' AS code
  UNION ALL
    SELECT 'BD-UPZ-87' AS parent_code, 'union' AS area_type, 'Baharchara' AS name, 'BD-UNION-879' AS code
  UNION ALL
    SELECT 'BD-UPZ-87' AS parent_code, 'union' AS area_type, 'Hnila' AS name, 'BD-UNION-880' AS code
  UNION ALL
    SELECT 'BD-UPZ-87' AS parent_code, 'union' AS area_type, 'Whykong' AS name, 'BD-UNION-881' AS code
  UNION ALL
    SELECT 'BD-UPZ-87' AS parent_code, 'union' AS area_type, 'Saintmartin' AS name, 'BD-UNION-882' AS code
  UNION ALL
    SELECT 'BD-UPZ-87' AS parent_code, 'union' AS area_type, 'Teknaf Sadar' AS name, 'BD-UNION-883' AS code
  UNION ALL
    SELECT 'BD-UPZ-88' AS parent_code, 'union' AS area_type, 'Khagrachhari Sadar' AS name, 'BD-UNION-884' AS code
  UNION ALL
    SELECT 'BD-UPZ-88' AS parent_code, 'union' AS area_type, 'Golabari' AS name, 'BD-UNION-885' AS code
  UNION ALL
    SELECT 'BD-UPZ-88' AS parent_code, 'union' AS area_type, 'Parachara' AS name, 'BD-UNION-886' AS code
  UNION ALL
    SELECT 'BD-UPZ-88' AS parent_code, 'union' AS area_type, 'Kamalchari' AS name, 'BD-UNION-887' AS code
  UNION ALL
    SELECT 'BD-UPZ-89' AS parent_code, 'union' AS area_type, 'Merung' AS name, 'BD-UNION-888' AS code
  UNION ALL
    SELECT 'BD-UPZ-89' AS parent_code, 'union' AS area_type, 'Boalkhali' AS name, 'BD-UNION-889' AS code
  UNION ALL
    SELECT 'BD-UPZ-89' AS parent_code, 'union' AS area_type, 'Kabakhali' AS name, 'BD-UNION-890' AS code
  UNION ALL
    SELECT 'BD-UPZ-89' AS parent_code, 'union' AS area_type, 'Dighinala' AS name, 'BD-UNION-891' AS code
  UNION ALL
    SELECT 'BD-UPZ-89' AS parent_code, 'union' AS area_type, 'Babuchara' AS name, 'BD-UNION-892' AS code
  UNION ALL
    SELECT 'BD-UPZ-90' AS parent_code, 'union' AS area_type, 'Logang' AS name, 'BD-UNION-893' AS code
  UNION ALL
    SELECT 'BD-UPZ-90' AS parent_code, 'union' AS area_type, 'Changi' AS name, 'BD-UNION-894' AS code
  UNION ALL
    SELECT 'BD-UPZ-90' AS parent_code, 'union' AS area_type, 'Panchari' AS name, 'BD-UNION-895' AS code
  UNION ALL
    SELECT 'BD-UPZ-90' AS parent_code, 'union' AS area_type, 'Latiban' AS name, 'BD-UNION-896' AS code
  UNION ALL
    SELECT 'BD-UPZ-91' AS parent_code, 'union' AS area_type, 'Dullyatali' AS name, 'BD-UNION-897' AS code
  UNION ALL
    SELECT 'BD-UPZ-91' AS parent_code, 'union' AS area_type, 'Barmachari' AS name, 'BD-UNION-898' AS code
  UNION ALL
    SELECT 'BD-UPZ-91' AS parent_code, 'union' AS area_type, 'Laxmichhari' AS name, 'BD-UNION-899' AS code
  UNION ALL
    SELECT 'BD-UPZ-92' AS parent_code, 'union' AS area_type, 'Bhaibonchara' AS name, 'BD-UNION-900' AS code
  UNION ALL
    SELECT 'BD-UPZ-92' AS parent_code, 'union' AS area_type, 'Mahalchari' AS name, 'BD-UNION-901' AS code
  UNION ALL
    SELECT 'BD-UPZ-92' AS parent_code, 'union' AS area_type, 'Mobachari' AS name, 'BD-UNION-902' AS code
  UNION ALL
    SELECT 'BD-UPZ-92' AS parent_code, 'union' AS area_type, 'Kayanghat' AS name, 'BD-UNION-903' AS code
  UNION ALL
    SELECT 'BD-UPZ-92' AS parent_code, 'union' AS area_type, 'Maischari' AS name, 'BD-UNION-904' AS code
  UNION ALL
    SELECT 'BD-UPZ-93' AS parent_code, 'union' AS area_type, 'Manikchari' AS name, 'BD-UNION-905' AS code
  UNION ALL
    SELECT 'BD-UPZ-93' AS parent_code, 'union' AS area_type, 'Batnatali' AS name, 'BD-UNION-906' AS code
  UNION ALL
    SELECT 'BD-UPZ-93' AS parent_code, 'union' AS area_type, 'Jogyachola' AS name, 'BD-UNION-907' AS code
  UNION ALL
    SELECT 'BD-UPZ-93' AS parent_code, 'union' AS area_type, 'Tintahari' AS name, 'BD-UNION-908' AS code
  UNION ALL
    SELECT 'BD-UPZ-94' AS parent_code, 'union' AS area_type, 'Ramgarh' AS name, 'BD-UNION-909' AS code
  UNION ALL
    SELECT 'BD-UPZ-94' AS parent_code, 'union' AS area_type, 'Patachara' AS name, 'BD-UNION-910' AS code
  UNION ALL
    SELECT 'BD-UPZ-94' AS parent_code, 'union' AS area_type, 'Hafchari' AS name, 'BD-UNION-911' AS code
  UNION ALL
    SELECT 'BD-UPZ-95' AS parent_code, 'union' AS area_type, 'Taindong' AS name, 'BD-UNION-912' AS code
  UNION ALL
    SELECT 'BD-UPZ-95' AS parent_code, 'union' AS area_type, 'Tabalchari' AS name, 'BD-UNION-913' AS code
  UNION ALL
    SELECT 'BD-UPZ-95' AS parent_code, 'union' AS area_type, 'Barnal' AS name, 'BD-UNION-914' AS code
  UNION ALL
    SELECT 'BD-UPZ-95' AS parent_code, 'union' AS area_type, 'Gomti' AS name, 'BD-UNION-915' AS code
  UNION ALL
    SELECT 'BD-UPZ-95' AS parent_code, 'union' AS area_type, 'Balchari' AS name, 'BD-UNION-916' AS code
  UNION ALL
    SELECT 'BD-UPZ-95' AS parent_code, 'union' AS area_type, 'Matiranga' AS name, 'BD-UNION-917' AS code
  UNION ALL
    SELECT 'BD-UPZ-95' AS parent_code, 'union' AS area_type, 'Guimara' AS name, 'BD-UNION-918' AS code
  UNION ALL
    SELECT 'BD-UPZ-95' AS parent_code, 'union' AS area_type, 'Amtali' AS name, 'BD-UNION-919' AS code
  UNION ALL
    SELECT 'BD-UPZ-97' AS parent_code, 'union' AS area_type, 'Rajbila' AS name, 'BD-UNION-920' AS code
  UNION ALL
    SELECT 'BD-UPZ-97' AS parent_code, 'union' AS area_type, 'Tongkaboty' AS name, 'BD-UNION-921' AS code
  UNION ALL
    SELECT 'BD-UPZ-97' AS parent_code, 'union' AS area_type, 'Suwalok' AS name, 'BD-UNION-922' AS code
  UNION ALL
    SELECT 'BD-UPZ-97' AS parent_code, 'union' AS area_type, 'Bandarban Sadar' AS name, 'BD-UNION-923' AS code
  UNION ALL
    SELECT 'BD-UPZ-97' AS parent_code, 'union' AS area_type, 'Kuhalong' AS name, 'BD-UNION-924' AS code
  UNION ALL
    SELECT 'BD-UPZ-98' AS parent_code, 'union' AS area_type, 'Alikadam Sadar' AS name, 'BD-UNION-925' AS code
  UNION ALL
    SELECT 'BD-UPZ-98' AS parent_code, 'union' AS area_type, 'Chwekhyong' AS name, 'BD-UNION-926' AS code
  UNION ALL
    SELECT 'BD-UPZ-99' AS parent_code, 'union' AS area_type, 'Naikhyongchari Sadar' AS name, 'BD-UNION-927' AS code
  UNION ALL
    SELECT 'BD-UPZ-99' AS parent_code, 'union' AS area_type, 'Gumdhum' AS name, 'BD-UNION-928' AS code
  UNION ALL
    SELECT 'BD-UPZ-99' AS parent_code, 'union' AS area_type, 'Baishari' AS name, 'BD-UNION-929' AS code
  UNION ALL
    SELECT 'BD-UPZ-99' AS parent_code, 'union' AS area_type, 'Sonaychari' AS name, 'BD-UNION-930' AS code
  UNION ALL
    SELECT 'BD-UPZ-99' AS parent_code, 'union' AS area_type, 'Duwchari' AS name, 'BD-UNION-931' AS code
  UNION ALL
    SELECT 'BD-UPZ-100' AS parent_code, 'union' AS area_type, 'Rowangchari Sadar' AS name, 'BD-UNION-932' AS code
  UNION ALL
    SELECT 'BD-UPZ-100' AS parent_code, 'union' AS area_type, 'Taracha' AS name, 'BD-UNION-933' AS code
  UNION ALL
    SELECT 'BD-UPZ-100' AS parent_code, 'union' AS area_type, 'Alekyong' AS name, 'BD-UNION-934' AS code
  UNION ALL
    SELECT 'BD-UPZ-100' AS parent_code, 'union' AS area_type, 'Nawapotong' AS name, 'BD-UNION-935' AS code
  UNION ALL
    SELECT 'BD-UPZ-101' AS parent_code, 'union' AS area_type, 'Gajalia' AS name, 'BD-UNION-936' AS code
  UNION ALL
    SELECT 'BD-UPZ-101' AS parent_code, 'union' AS area_type, 'Lama Sadar' AS name, 'BD-UNION-937' AS code
  UNION ALL
    SELECT 'BD-UPZ-101' AS parent_code, 'union' AS area_type, 'Fasiakhali' AS name, 'BD-UNION-938' AS code
  UNION ALL
    SELECT 'BD-UPZ-101' AS parent_code, 'union' AS area_type, 'Fythong' AS name, 'BD-UNION-939' AS code
  UNION ALL
    SELECT 'BD-UPZ-101' AS parent_code, 'union' AS area_type, 'Rupushipara' AS name, 'BD-UNION-940' AS code
  UNION ALL
    SELECT 'BD-UPZ-101' AS parent_code, 'union' AS area_type, 'Sarai' AS name, 'BD-UNION-941' AS code
  UNION ALL
    SELECT 'BD-UPZ-101' AS parent_code, 'union' AS area_type, 'Aziznagar' AS name, 'BD-UNION-942' AS code
  UNION ALL
    SELECT 'BD-UPZ-102' AS parent_code, 'union' AS area_type, 'Paind' AS name, 'BD-UNION-943' AS code
  UNION ALL
    SELECT 'BD-UPZ-102' AS parent_code, 'union' AS area_type, 'Ruma Sadar' AS name, 'BD-UNION-944' AS code
  UNION ALL
    SELECT 'BD-UPZ-102' AS parent_code, 'union' AS area_type, 'Ramakreprangsa' AS name, 'BD-UNION-945' AS code
  UNION ALL
    SELECT 'BD-UPZ-102' AS parent_code, 'union' AS area_type, 'Galanggya' AS name, 'BD-UNION-946' AS code
  UNION ALL
    SELECT 'BD-UPZ-103' AS parent_code, 'union' AS area_type, 'Remakre' AS name, 'BD-UNION-947' AS code
  UNION ALL
    SELECT 'BD-UPZ-103' AS parent_code, 'union' AS area_type, 'Tind' AS name, 'BD-UNION-948' AS code
  UNION ALL
    SELECT 'BD-UPZ-103' AS parent_code, 'union' AS area_type, 'Thanchi Sadar' AS name, 'BD-UNION-949' AS code
  UNION ALL
    SELECT 'BD-UPZ-103' AS parent_code, 'union' AS area_type, 'Balipara' AS name, 'BD-UNION-950' AS code
  UNION ALL
    SELECT 'BD-UPZ-104' AS parent_code, 'union' AS area_type, 'Rajapur' AS name, 'BD-UNION-951' AS code
  UNION ALL
    SELECT 'BD-UPZ-104' AS parent_code, 'union' AS area_type, 'Baradhul' AS name, 'BD-UNION-952' AS code
  UNION ALL
    SELECT 'BD-UPZ-104' AS parent_code, 'union' AS area_type, 'Belkuchi Sadar' AS name, 'BD-UNION-953' AS code
  UNION ALL
    SELECT 'BD-UPZ-104' AS parent_code, 'union' AS area_type, 'Dhukuriabera' AS name, 'BD-UNION-954' AS code
  UNION ALL
    SELECT 'BD-UPZ-104' AS parent_code, 'union' AS area_type, 'Doulatpur' AS name, 'BD-UNION-955' AS code
  UNION ALL
    SELECT 'BD-UPZ-104' AS parent_code, 'union' AS area_type, 'Bhangabari' AS name, 'BD-UNION-956' AS code
  UNION ALL
    SELECT 'BD-UPZ-105' AS parent_code, 'union' AS area_type, 'Baghutia' AS name, 'BD-UNION-957' AS code
  UNION ALL
    SELECT 'BD-UPZ-105' AS parent_code, 'union' AS area_type, 'Gharjan' AS name, 'BD-UNION-958' AS code
  UNION ALL
    SELECT 'BD-UPZ-105' AS parent_code, 'union' AS area_type, 'Khaskaulia' AS name, 'BD-UNION-959' AS code
  UNION ALL
    SELECT 'BD-UPZ-105' AS parent_code, 'union' AS area_type, 'Khaspukuria' AS name, 'BD-UNION-960' AS code
  UNION ALL
    SELECT 'BD-UPZ-105' AS parent_code, 'union' AS area_type, 'Omarpur' AS name, 'BD-UNION-961' AS code
  UNION ALL
    SELECT 'BD-UPZ-105' AS parent_code, 'union' AS area_type, 'Sadia Chandpur' AS name, 'BD-UNION-962' AS code
  UNION ALL
    SELECT 'BD-UPZ-105' AS parent_code, 'union' AS area_type, 'Sthal' AS name, 'BD-UNION-963' AS code
  UNION ALL
    SELECT 'BD-UPZ-106' AS parent_code, 'union' AS area_type, 'Bhadraghat' AS name, 'BD-UNION-964' AS code
  UNION ALL
    SELECT 'BD-UPZ-106' AS parent_code, 'union' AS area_type, 'Jamtail' AS name, 'BD-UNION-965' AS code
  UNION ALL
    SELECT 'BD-UPZ-106' AS parent_code, 'union' AS area_type, 'Jhawail' AS name, 'BD-UNION-966' AS code
  UNION ALL
    SELECT 'BD-UPZ-106' AS parent_code, 'union' AS area_type, 'Roydaulatpur' AS name, 'BD-UNION-967' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Chalitadangha' AS name, 'BD-UNION-968' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Chargirish' AS name, 'BD-UNION-969' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Gandail' AS name, 'BD-UNION-970' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Kazipur Sadar' AS name, 'BD-UNION-971' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Khasrajbari' AS name, 'BD-UNION-972' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Maijbari' AS name, 'BD-UNION-973' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Monsur Nagar' AS name, 'BD-UNION-974' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Natuarpara' AS name, 'BD-UNION-975' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Nishchintapur' AS name, 'BD-UNION-976' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Sonamukhi' AS name, 'BD-UNION-977' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Subhagacha' AS name, 'BD-UNION-978' AS code
  UNION ALL
    SELECT 'BD-UPZ-107' AS parent_code, 'union' AS area_type, 'Tekani' AS name, 'BD-UNION-979' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Brommogacha' AS name, 'BD-UNION-980' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Chandaikona' AS name, 'BD-UNION-981' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Dhamainagar' AS name, 'BD-UNION-982' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Dhangora' AS name, 'BD-UNION-983' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Dhubil' AS name, 'BD-UNION-984' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Ghurka' AS name, 'BD-UNION-985' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Nalka' AS name, 'BD-UNION-986' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Pangashi' AS name, 'BD-UNION-987' AS code
  UNION ALL
    SELECT 'BD-UPZ-108' AS parent_code, 'union' AS area_type, 'Sonakhara' AS name, 'BD-UNION-988' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Beltail' AS name, 'BD-UNION-989' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Jalalpur' AS name, 'BD-UNION-990' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Kayempure' AS name, 'BD-UNION-991' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Garadah' AS name, 'BD-UNION-992' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Potazia' AS name, 'BD-UNION-993' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Rupbati' AS name, 'BD-UNION-994' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Gala' AS name, 'BD-UNION-995' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Porzona' AS name, 'BD-UNION-996' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Habibullah Nagar' AS name, 'BD-UNION-997' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Khukni' AS name, 'BD-UNION-998' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Koizuri' AS name, 'BD-UNION-999' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Sonatoni' AS name, 'BD-UNION-1000' AS code
  UNION ALL
    SELECT 'BD-UPZ-109' AS parent_code, 'union' AS area_type, 'Narina' AS name, 'BD-UNION-1001' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Bagbati' AS name, 'BD-UNION-1002' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Ratankandi' AS name, 'BD-UNION-1003' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Bohuli' AS name, 'BD-UNION-1004' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Sheyalkol' AS name, 'BD-UNION-1005' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Khokshabari' AS name, 'BD-UNION-1006' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Songacha' AS name, 'BD-UNION-1007' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Mesra' AS name, 'BD-UNION-1008' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Kowakhola' AS name, 'BD-UNION-1009' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Kaliahoripur' AS name, 'BD-UNION-1010' AS code
  UNION ALL
    SELECT 'BD-UPZ-110' AS parent_code, 'union' AS area_type, 'Soydabad' AS name, 'BD-UNION-1011' AS code
  UNION ALL
    SELECT 'BD-UPZ-111' AS parent_code, 'union' AS area_type, 'Baruhas' AS name, 'BD-UNION-1012' AS code
  UNION ALL
    SELECT 'BD-UPZ-111' AS parent_code, 'union' AS area_type, 'Talam' AS name, 'BD-UNION-1013' AS code
  UNION ALL
    SELECT 'BD-UPZ-111' AS parent_code, 'union' AS area_type, 'Soguna' AS name, 'BD-UNION-1014' AS code
  UNION ALL
    SELECT 'BD-UPZ-111' AS parent_code, 'union' AS area_type, 'Magura Binod' AS name, 'BD-UNION-1015' AS code
  UNION ALL
    SELECT 'BD-UPZ-111' AS parent_code, 'union' AS area_type, 'Naogaon' AS name, 'BD-UNION-1016' AS code
  UNION ALL
    SELECT 'BD-UPZ-111' AS parent_code, 'union' AS area_type, 'Tarash Sadar' AS name, 'BD-UNION-1017' AS code
  UNION ALL
    SELECT 'BD-UPZ-111' AS parent_code, 'union' AS area_type, 'Madhainagar' AS name, 'BD-UNION-1018' AS code
  UNION ALL
    SELECT 'BD-UPZ-111' AS parent_code, 'union' AS area_type, 'Deshigram' AS name, 'BD-UNION-1019' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Ullapara Sadar' AS name, 'BD-UNION-1020' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Ramkrisnopur' AS name, 'BD-UNION-1021' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Bangala' AS name, 'BD-UNION-1022' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Udhunia' AS name, 'BD-UNION-1023' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Boropangashi' AS name, 'BD-UNION-1024' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Durga Nagar' AS name, 'BD-UNION-1025' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Purnimagati' AS name, 'BD-UNION-1026' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Salanga' AS name, 'BD-UNION-1027' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Hatikumrul' AS name, 'BD-UNION-1028' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Borohor' AS name, 'BD-UNION-1029' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Ponchocroshi' AS name, 'BD-UNION-1030' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Salo' AS name, 'BD-UNION-1031' AS code
  UNION ALL
    SELECT 'BD-UPZ-112' AS parent_code, 'union' AS area_type, 'Mohonpur' AS name, 'BD-UNION-1032' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Vaina' AS name, 'BD-UNION-1033' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Tantibonda' AS name, 'BD-UNION-1034' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Manikhat' AS name, 'BD-UNION-1035' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Dulai' AS name, 'BD-UNION-1036' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Ahammadpur' AS name, 'BD-UNION-1037' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Raninagar' AS name, 'BD-UNION-1038' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Satbaria' AS name, 'BD-UNION-1039' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Hatkhali' AS name, 'BD-UNION-1040' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Nazirganj' AS name, 'BD-UNION-1041' AS code
  UNION ALL
    SELECT 'BD-UPZ-113' AS parent_code, 'union' AS area_type, 'Sagorkandi' AS name, 'BD-UNION-1042' AS code
  UNION ALL
    SELECT 'BD-UPZ-114' AS parent_code, 'union' AS area_type, 'Sara' AS name, 'BD-UNION-1043' AS code
  UNION ALL
    SELECT 'BD-UPZ-114' AS parent_code, 'union' AS area_type, 'Pakshi' AS name, 'BD-UNION-1044' AS code
  UNION ALL
    SELECT 'BD-UPZ-114' AS parent_code, 'union' AS area_type, 'Muladuli' AS name, 'BD-UNION-1045' AS code
  UNION ALL
    SELECT 'BD-UPZ-114' AS parent_code, 'union' AS area_type, 'Dashuria' AS name, 'BD-UNION-1046' AS code
  UNION ALL
    SELECT 'BD-UPZ-114' AS parent_code, 'union' AS area_type, 'Silimpur' AS name, 'BD-UNION-1047' AS code
  UNION ALL
    SELECT 'BD-UPZ-114' AS parent_code, 'union' AS area_type, 'Sahapur' AS name, 'BD-UNION-1048' AS code
  UNION ALL
    SELECT 'BD-UPZ-114' AS parent_code, 'union' AS area_type, 'Luxmikunda' AS name, 'BD-UNION-1049' AS code
  UNION ALL
    SELECT 'BD-UPZ-115' AS parent_code, 'union' AS area_type, 'Bhangura' AS name, 'BD-UNION-1050' AS code
  UNION ALL
    SELECT 'BD-UPZ-115' AS parent_code, 'union' AS area_type, 'Khanmarich' AS name, 'BD-UNION-1051' AS code
  UNION ALL
    SELECT 'BD-UPZ-115' AS parent_code, 'union' AS area_type, 'Ashtamanisha' AS name, 'BD-UNION-1052' AS code
  UNION ALL
    SELECT 'BD-UPZ-115' AS parent_code, 'union' AS area_type, 'Dilpasar' AS name, 'BD-UNION-1053' AS code
  UNION ALL
    SELECT 'BD-UPZ-115' AS parent_code, 'union' AS area_type, 'Parbhangura' AS name, 'BD-UNION-1054' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Maligachha' AS name, 'BD-UNION-1055' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Malanchi' AS name, 'BD-UNION-1056' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Gayeshpur' AS name, 'BD-UNION-1057' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Ataikula' AS name, 'BD-UNION-1058' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Chartarapur' AS name, 'BD-UNION-1059' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Sadullahpur' AS name, 'BD-UNION-1060' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Bharara' AS name, 'BD-UNION-1061' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Dogachi' AS name, 'BD-UNION-1062' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Hemayetpur' AS name, 'BD-UNION-1063' AS code
  UNION ALL
    SELECT 'BD-UPZ-116' AS parent_code, 'union' AS area_type, 'Dapunia' AS name, 'BD-UNION-1064' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Haturia Nakalia' AS name, 'BD-UNION-1065' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Notun Varenga' AS name, 'BD-UNION-1066' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Koitola' AS name, 'BD-UNION-1067' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Chakla' AS name, 'BD-UNION-1068' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Jatsakhini' AS name, 'BD-UNION-1069' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Puran Varenga' AS name, 'BD-UNION-1070' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Ruppur' AS name, 'BD-UNION-1071' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Masumdia' AS name, 'BD-UNION-1072' AS code
  UNION ALL
    SELECT 'BD-UPZ-117' AS parent_code, 'union' AS area_type, 'Dhalar Char' AS name, 'BD-UNION-1073' AS code
  UNION ALL
    SELECT 'BD-UPZ-118' AS parent_code, 'union' AS area_type, 'Majhpara' AS name, 'BD-UNION-1074' AS code
  UNION ALL
    SELECT 'BD-UPZ-118' AS parent_code, 'union' AS area_type, 'Chandba' AS name, 'BD-UNION-1075' AS code
  UNION ALL
    SELECT 'BD-UPZ-118' AS parent_code, 'union' AS area_type, 'Debottar' AS name, 'BD-UNION-1076' AS code
  UNION ALL
    SELECT 'BD-UPZ-118' AS parent_code, 'union' AS area_type, 'Ekdanta' AS name, 'BD-UNION-1077' AS code
  UNION ALL
    SELECT 'BD-UPZ-118' AS parent_code, 'union' AS area_type, 'Laxshmipur' AS name, 'BD-UNION-1078' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Handial' AS name, 'BD-UNION-1079' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Chhaikola' AS name, 'BD-UNION-1080' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Nimaichara' AS name, 'BD-UNION-1081' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Gunaigachha' AS name, 'BD-UNION-1082' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Parshadanga' AS name, 'BD-UNION-1083' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Failjana' AS name, 'BD-UNION-1084' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Mulgram' AS name, 'BD-UNION-1085' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Haripur' AS name, 'BD-UNION-1086' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Mothurapur' AS name, 'BD-UNION-1087' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Bilchalan' AS name, 'BD-UNION-1088' AS code
  UNION ALL
    SELECT 'BD-UPZ-119' AS parent_code, 'union' AS area_type, 'Danthia Bamangram' AS name, 'BD-UNION-1089' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Nagdemra' AS name, 'BD-UNION-1090' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Dhulauri' AS name, 'BD-UNION-1091' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Bhulbaria' AS name, 'BD-UNION-1092' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Dhopadaha' AS name, 'BD-UNION-1093' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Karamja' AS name, 'BD-UNION-1094' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Kashinathpur' AS name, 'BD-UNION-1095' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Gaurigram' AS name, 'BD-UNION-1096' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Nandanpur' AS name, 'BD-UNION-1097' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Khetupara' AS name, 'BD-UNION-1098' AS code
  UNION ALL
    SELECT 'BD-UPZ-120' AS parent_code, 'union' AS area_type, 'Ar-Ataikula' AS name, 'BD-UNION-1099' AS code
  UNION ALL
    SELECT 'BD-UPZ-121' AS parent_code, 'union' AS area_type, 'Brilahiribari' AS name, 'BD-UNION-1100' AS code
  UNION ALL
    SELECT 'BD-UPZ-121' AS parent_code, 'union' AS area_type, 'Pungali' AS name, 'BD-UNION-1101' AS code
  UNION ALL
    SELECT 'BD-UPZ-121' AS parent_code, 'union' AS area_type, 'Faridpur' AS name, 'BD-UNION-1102' AS code
  UNION ALL
    SELECT 'BD-UPZ-121' AS parent_code, 'union' AS area_type, 'Hadal' AS name, 'BD-UNION-1103' AS code
  UNION ALL
    SELECT 'BD-UPZ-121' AS parent_code, 'union' AS area_type, 'Banwarinagar' AS name, 'BD-UNION-1104' AS code
  UNION ALL
    SELECT 'BD-UPZ-121' AS parent_code, 'union' AS area_type, 'Demra' AS name, 'BD-UNION-1105' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Birkedar' AS name, 'BD-UNION-1106' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Kalai' AS name, 'BD-UNION-1107' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Paikar' AS name, 'BD-UNION-1108' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Narhatta' AS name, 'BD-UNION-1109' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Murail' AS name, 'BD-UNION-1110' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Kahaloo' AS name, 'BD-UNION-1111' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-1112' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Jamgaon' AS name, 'BD-UNION-1113' AS code
  UNION ALL
    SELECT 'BD-UPZ-122' AS parent_code, 'union' AS area_type, 'Malancha' AS name, 'BD-UNION-1114' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Fapore' AS name, 'BD-UNION-1115' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Shabgram' AS name, 'BD-UNION-1116' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Nishindara' AS name, 'BD-UNION-1117' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Erulia' AS name, 'BD-UNION-1118' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Rajapur' AS name, 'BD-UNION-1119' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Shakharia' AS name, 'BD-UNION-1120' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Sekherkola' AS name, 'BD-UNION-1121' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Gokul' AS name, 'BD-UNION-1122' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Noongola' AS name, 'BD-UNION-1123' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Lahiripara' AS name, 'BD-UNION-1124' AS code
  UNION ALL
    SELECT 'BD-UPZ-123' AS parent_code, 'union' AS area_type, 'Namuja' AS name, 'BD-UNION-1125' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Sariakandi Sadar' AS name, 'BD-UNION-1126' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Narchi' AS name, 'BD-UNION-1127' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Bohail' AS name, 'BD-UNION-1128' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Chaluabari' AS name, 'BD-UNION-1129' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Chandanbaisha' AS name, 'BD-UNION-1130' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Hatfulbari' AS name, 'BD-UNION-1131' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Hatsherpur' AS name, 'BD-UNION-1132' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Karnibari' AS name, 'BD-UNION-1133' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Kazla' AS name, 'BD-UNION-1134' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Kutubpur' AS name, 'BD-UNION-1135' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Kamalpur' AS name, 'BD-UNION-1136' AS code
  UNION ALL
    SELECT 'BD-UPZ-124' AS parent_code, 'union' AS area_type, 'Bhelabari' AS name, 'BD-UNION-1137' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Asekpur' AS name, 'BD-UNION-1138' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Madla' AS name, 'BD-UNION-1139' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Majhira' AS name, 'BD-UNION-1140' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Aria' AS name, 'BD-UNION-1141' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Kharna' AS name, 'BD-UNION-1142' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Khottapara' AS name, 'BD-UNION-1143' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Chopinagar' AS name, 'BD-UNION-1144' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Amrul' AS name, 'BD-UNION-1145' AS code
  UNION ALL
    SELECT 'BD-UPZ-125' AS parent_code, 'union' AS area_type, 'Gohail' AS name, 'BD-UNION-1146' AS code
  UNION ALL
    SELECT 'BD-UPZ-126' AS parent_code, 'union' AS area_type, 'Zianagar' AS name, 'BD-UNION-1147' AS code
  UNION ALL
    SELECT 'BD-UPZ-126' AS parent_code, 'union' AS area_type, 'Chamrul' AS name, 'BD-UNION-1148' AS code
  UNION ALL
    SELECT 'BD-UPZ-126' AS parent_code, 'union' AS area_type, 'Dupchanchia' AS name, 'BD-UNION-1149' AS code
  UNION ALL
    SELECT 'BD-UPZ-126' AS parent_code, 'union' AS area_type, 'Gunahar' AS name, 'BD-UNION-1150' AS code
  UNION ALL
    SELECT 'BD-UPZ-126' AS parent_code, 'union' AS area_type, 'Gobindapur' AS name, 'BD-UNION-1151' AS code
  UNION ALL
    SELECT 'BD-UPZ-126' AS parent_code, 'union' AS area_type, 'Talora' AS name, 'BD-UNION-1152' AS code
  UNION ALL
    SELECT 'BD-UPZ-127' AS parent_code, 'union' AS area_type, 'Chhatiangram' AS name, 'BD-UNION-1153' AS code
  UNION ALL
    SELECT 'BD-UPZ-127' AS parent_code, 'union' AS area_type, 'Nasaratpur' AS name, 'BD-UNION-1154' AS code
  UNION ALL
    SELECT 'BD-UPZ-127' AS parent_code, 'union' AS area_type, 'Adamdighi' AS name, 'BD-UNION-1155' AS code
  UNION ALL
    SELECT 'BD-UPZ-127' AS parent_code, 'union' AS area_type, 'Kundagram' AS name, 'BD-UNION-1156' AS code
  UNION ALL
    SELECT 'BD-UPZ-127' AS parent_code, 'union' AS area_type, 'Chapapur' AS name, 'BD-UNION-1157' AS code
  UNION ALL
    SELECT 'BD-UPZ-127' AS parent_code, 'union' AS area_type, 'Shantahar' AS name, 'BD-UNION-1158' AS code
  UNION ALL
    SELECT 'BD-UPZ-128' AS parent_code, 'union' AS area_type, 'Burail' AS name, 'BD-UNION-1159' AS code
  UNION ALL
    SELECT 'BD-UPZ-128' AS parent_code, 'union' AS area_type, 'Nandigram' AS name, 'BD-UNION-1160' AS code
  UNION ALL
    SELECT 'BD-UPZ-128' AS parent_code, 'union' AS area_type, 'Bhatra' AS name, 'BD-UNION-1161' AS code
  UNION ALL
    SELECT 'BD-UPZ-128' AS parent_code, 'union' AS area_type, 'Thalta Majhgram' AS name, 'BD-UNION-1162' AS code
  UNION ALL
    SELECT 'BD-UPZ-128' AS parent_code, 'union' AS area_type, 'Bhatgram' AS name, 'BD-UNION-1163' AS code
  UNION ALL
    SELECT 'BD-UPZ-129' AS parent_code, 'union' AS area_type, 'Sonatala' AS name, 'BD-UNION-1164' AS code
  UNION ALL
    SELECT 'BD-UPZ-129' AS parent_code, 'union' AS area_type, 'Balua' AS name, 'BD-UNION-1165' AS code
  UNION ALL
    SELECT 'BD-UPZ-129' AS parent_code, 'union' AS area_type, 'Zorgacha' AS name, 'BD-UNION-1166' AS code
  UNION ALL
    SELECT 'BD-UPZ-129' AS parent_code, 'union' AS area_type, 'Digdair' AS name, 'BD-UNION-1167' AS code
  UNION ALL
    SELECT 'BD-UPZ-129' AS parent_code, 'union' AS area_type, 'Madhupur' AS name, 'BD-UNION-1168' AS code
  UNION ALL
    SELECT 'BD-UPZ-129' AS parent_code, 'union' AS area_type, 'Pakulla' AS name, 'BD-UNION-1169' AS code
  UNION ALL
    SELECT 'BD-UPZ-129' AS parent_code, 'union' AS area_type, 'Tekani Chukinagar' AS name, 'BD-UNION-1170' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Nimgachi' AS name, 'BD-UNION-1171' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Kalerpara' AS name, 'BD-UNION-1172' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Chikashi' AS name, 'BD-UNION-1173' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Gossainbari' AS name, 'BD-UNION-1174' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Bhandarbari' AS name, 'BD-UNION-1175' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Gopalnagar' AS name, 'BD-UNION-1176' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Mothurapur' AS name, 'BD-UNION-1177' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Chowkibari' AS name, 'BD-UNION-1178' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Elangi' AS name, 'BD-UNION-1179' AS code
  UNION ALL
    SELECT 'BD-UPZ-130' AS parent_code, 'union' AS area_type, 'Dhunat Sadar' AS name, 'BD-UNION-1180' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Baliadighi' AS name, 'BD-UNION-1181' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Dakshinpara' AS name, 'BD-UNION-1182' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Durgahata' AS name, 'BD-UNION-1183' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Kagail' AS name, 'BD-UNION-1184' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Sonarai' AS name, 'BD-UNION-1185' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Rameshwarpur' AS name, 'BD-UNION-1186' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Naruamala' AS name, 'BD-UNION-1187' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Nepaltali' AS name, 'BD-UNION-1188' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Gabtali' AS name, 'BD-UNION-1189' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Mahishaban' AS name, 'BD-UNION-1190' AS code
  UNION ALL
    SELECT 'BD-UPZ-131' AS parent_code, 'union' AS area_type, 'Nasipur' AS name, 'BD-UNION-1191' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Mirzapur' AS name, 'BD-UNION-1192' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Khamarkandi' AS name, 'BD-UNION-1193' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Garidaha' AS name, 'BD-UNION-1194' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Kusumbi' AS name, 'BD-UNION-1195' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Bishalpur' AS name, 'BD-UNION-1196' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Shimabari' AS name, 'BD-UNION-1197' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Shahbondegi' AS name, 'BD-UNION-1198' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Sughat' AS name, 'BD-UNION-1199' AS code
  UNION ALL
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Khanpur' AS name, 'BD-UNION-1200' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;