INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-44' AS parent_code, 'union' AS area_type, 'Charkakra' AS name, 'BD-UNION-401' AS code
  UNION ALL
    SELECT 'BD-UPZ-44' AS parent_code, 'union' AS area_type, 'Charfakira' AS name, 'BD-UNION-402' AS code
  UNION ALL
    SELECT 'BD-UPZ-44' AS parent_code, 'union' AS area_type, 'Musapur' AS name, 'BD-UNION-403' AS code
  UNION ALL
    SELECT 'BD-UPZ-44' AS parent_code, 'union' AS area_type, 'Charelahi' AS name, 'BD-UNION-404' AS code
  UNION ALL
    SELECT 'BD-UPZ-44' AS parent_code, 'union' AS area_type, 'Rampur' AS name, 'BD-UNION-405' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Amanullapur' AS name, 'BD-UNION-406' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Gopalpur' AS name, 'BD-UNION-407' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Jirtali' AS name, 'BD-UNION-408' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Kutubpur' AS name, 'BD-UNION-409' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Alyearpur' AS name, 'BD-UNION-410' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Chayani' AS name, 'BD-UNION-411' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Rajganj' AS name, 'BD-UNION-412' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Eklashpur' AS name, 'BD-UNION-413' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Begumganj' AS name, 'BD-UNION-414' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Mirwarishpur' AS name, 'BD-UNION-415' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Narottampur' AS name, 'BD-UNION-416' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-417' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Rasulpur' AS name, 'BD-UNION-418' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Hajipur' AS name, 'BD-UNION-419' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Sharifpur' AS name, 'BD-UNION-420' AS code
  UNION ALL
    SELECT 'BD-UPZ-45' AS parent_code, 'union' AS area_type, 'Kadirpur' AS name, 'BD-UNION-421' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Sukhchar' AS name, 'BD-UNION-422' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Nolchira' AS name, 'BD-UNION-423' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Charishwar' AS name, 'BD-UNION-424' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Charking' AS name, 'BD-UNION-425' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Tomoroddi' AS name, 'BD-UNION-426' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Sonadiya' AS name, 'BD-UNION-427' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Burirchar' AS name, 'BD-UNION-428' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Jahajmara' AS name, 'BD-UNION-429' AS code
  UNION ALL
    SELECT 'BD-UPZ-46' AS parent_code, 'union' AS area_type, 'Nijhumdwi' AS name, 'BD-UNION-430' AS code
  UNION ALL
    SELECT 'BD-UPZ-47' AS parent_code, 'union' AS area_type, 'Charjabbar' AS name, 'BD-UNION-431' AS code
  UNION ALL
    SELECT 'BD-UPZ-47' AS parent_code, 'union' AS area_type, 'Charbata' AS name, 'BD-UNION-432' AS code
  UNION ALL
    SELECT 'BD-UPZ-47' AS parent_code, 'union' AS area_type, 'Charclerk' AS name, 'BD-UNION-433' AS code
  UNION ALL
    SELECT 'BD-UPZ-47' AS parent_code, 'union' AS area_type, 'Charwapda' AS name, 'BD-UNION-434' AS code
  UNION ALL
    SELECT 'BD-UPZ-47' AS parent_code, 'union' AS area_type, 'Charjubilee' AS name, 'BD-UNION-435' AS code
  UNION ALL
    SELECT 'BD-UPZ-47' AS parent_code, 'union' AS area_type, 'Charaman Ullah' AS name, 'BD-UNION-436' AS code
  UNION ALL
    SELECT 'BD-UPZ-47' AS parent_code, 'union' AS area_type, 'East Charbata' AS name, 'BD-UNION-437' AS code
  UNION ALL
    SELECT 'BD-UPZ-47' AS parent_code, 'union' AS area_type, 'Mohammadpur' AS name, 'BD-UNION-438' AS code
  UNION ALL
    SELECT 'BD-UPZ-48' AS parent_code, 'union' AS area_type, 'Narottampur' AS name, 'BD-UNION-439' AS code
  UNION ALL
    SELECT 'BD-UPZ-48' AS parent_code, 'union' AS area_type, 'Dhanshiri' AS name, 'BD-UNION-440' AS code
  UNION ALL
    SELECT 'BD-UPZ-48' AS parent_code, 'union' AS area_type, 'Sundalpur' AS name, 'BD-UNION-441' AS code
  UNION ALL
    SELECT 'BD-UPZ-48' AS parent_code, 'union' AS area_type, 'Ghoshbag' AS name, 'BD-UNION-442' AS code
  UNION ALL
    SELECT 'BD-UPZ-48' AS parent_code, 'union' AS area_type, 'Chaprashirhat' AS name, 'BD-UNION-443' AS code
  UNION ALL
    SELECT 'BD-UPZ-48' AS parent_code, 'union' AS area_type, 'Dhanshalik' AS name, 'BD-UNION-444' AS code
  UNION ALL
    SELECT 'BD-UPZ-48' AS parent_code, 'union' AS area_type, 'Batoiya' AS name, 'BD-UNION-445' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Chhatarpaia' AS name, 'BD-UNION-446' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Kesharpar' AS name, 'BD-UNION-447' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Dumurua' AS name, 'BD-UNION-448' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Kadra' AS name, 'BD-UNION-449' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Arjuntala' AS name, 'BD-UNION-450' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Kabilpur' AS name, 'BD-UNION-451' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Mohammadpur' AS name, 'BD-UNION-452' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Nabipur' AS name, 'BD-UNION-453' AS code
  UNION ALL
    SELECT 'BD-UPZ-49' AS parent_code, 'union' AS area_type, 'Bejbagh' AS name, 'BD-UNION-454' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Sahapur' AS name, 'BD-UNION-455' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Ramnarayanpur' AS name, 'BD-UNION-456' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Porokote' AS name, 'BD-UNION-457' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Badalkot' AS name, 'BD-UNION-458' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Panchgaon' AS name, 'BD-UNION-459' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Hat-Pukuria Ghatlabag' AS name, 'BD-UNION-460' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Noakhala' AS name, 'BD-UNION-461' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Khilpara' AS name, 'BD-UNION-462' AS code
  UNION ALL
    SELECT 'BD-UPZ-50' AS parent_code, 'union' AS area_type, 'Mohammadpur' AS name, 'BD-UNION-463' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Joyag' AS name, 'BD-UNION-464' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Nodona' AS name, 'BD-UNION-465' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Chashirhat' AS name, 'BD-UNION-466' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Barogaon' AS name, 'BD-UNION-467' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Ambarnagor' AS name, 'BD-UNION-468' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Nateshwar' AS name, 'BD-UNION-469' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Bajra' AS name, 'BD-UNION-470' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Sonapur' AS name, 'BD-UNION-471' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Deoti' AS name, 'BD-UNION-472' AS code
  UNION ALL
    SELECT 'BD-UPZ-51' AS parent_code, 'union' AS area_type, 'Amishapara' AS name, 'BD-UNION-473' AS code
  UNION ALL
    SELECT 'BD-UPZ-52' AS parent_code, 'union' AS area_type, 'Gazipur' AS name, 'BD-UNION-474' AS code
  UNION ALL
    SELECT 'BD-UPZ-52' AS parent_code, 'union' AS area_type, 'Algidurgapur (North)' AS name, 'BD-UNION-475' AS code
  UNION ALL
    SELECT 'BD-UPZ-52' AS parent_code, 'union' AS area_type, 'Algidurgapur (South)' AS name, 'BD-UNION-476' AS code
  UNION ALL
    SELECT 'BD-UPZ-52' AS parent_code, 'union' AS area_type, 'Nilkamal' AS name, 'BD-UNION-477' AS code
  UNION ALL
    SELECT 'BD-UPZ-52' AS parent_code, 'union' AS area_type, 'Haimchar' AS name, 'BD-UNION-478' AS code
  UNION ALL
    SELECT 'BD-UPZ-52' AS parent_code, 'union' AS area_type, 'Charbhairabi' AS name, 'BD-UNION-479' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Pathair' AS name, 'BD-UNION-480' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Bitara' AS name, 'BD-UNION-481' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Shohodebpur (East)' AS name, 'BD-UNION-482' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Shohodebpur (West)' AS name, 'BD-UNION-483' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Kachua (North)' AS name, 'BD-UNION-484' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Kachua (South)' AS name, 'BD-UNION-485' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Gohat (North)' AS name, 'BD-UNION-486' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Kadla' AS name, 'BD-UNION-487' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Ashrafpur' AS name, 'BD-UNION-488' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Gohat (South)' AS name, 'BD-UNION-489' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Sachar' AS name, 'BD-UNION-490' AS code
  UNION ALL
    SELECT 'BD-UPZ-53' AS parent_code, 'union' AS area_type, 'Koroia' AS name, 'BD-UNION-491' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Tamta (South)' AS name, 'BD-UNION-492' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Tamta (North)' AS name, 'BD-UNION-493' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Meher (North)' AS name, 'BD-UNION-494' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Meher (South)' AS name, 'BD-UNION-495' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Suchipara (North)' AS name, 'BD-UNION-496' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Suchipara (South)' AS name, 'BD-UNION-497' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Chitoshi (East)' AS name, 'BD-UNION-498' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Raysree (South)' AS name, 'BD-UNION-499' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Raysree (North)' AS name, 'BD-UNION-500' AS code
  UNION ALL
    SELECT 'BD-UPZ-54' AS parent_code, 'union' AS area_type, 'Chitoshiwest' AS name, 'BD-UNION-501' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Bishnapur' AS name, 'BD-UNION-502' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Ashikati' AS name, 'BD-UNION-503' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Shahmahmudpur' AS name, 'BD-UNION-504' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Kalyanpur' AS name, 'BD-UNION-505' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Rampur' AS name, 'BD-UNION-506' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Maishadi' AS name, 'BD-UNION-507' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Tarpurchandi' AS name, 'BD-UNION-508' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Baghadi' AS name, 'BD-UNION-509' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Laxmipur Model' AS name, 'BD-UNION-510' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Hanarchar' AS name, 'BD-UNION-511' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Chandra' AS name, 'BD-UNION-512' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Rajrajeshwar' AS name, 'BD-UNION-513' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Ibrahimpur' AS name, 'BD-UNION-514' AS code
  UNION ALL
    SELECT 'BD-UPZ-55' AS parent_code, 'union' AS area_type, 'Balia' AS name, 'BD-UNION-515' AS code
  UNION ALL
    SELECT 'BD-UPZ-56' AS parent_code, 'union' AS area_type, 'Nayergaon (North)' AS name, 'BD-UNION-516' AS code
  UNION ALL
    SELECT 'BD-UPZ-56' AS parent_code, 'union' AS area_type, 'Nayergaon (South)' AS name, 'BD-UNION-517' AS code
  UNION ALL
    SELECT 'BD-UPZ-56' AS parent_code, 'union' AS area_type, 'Khadergaon' AS name, 'BD-UNION-518' AS code
  UNION ALL
    SELECT 'BD-UPZ-56' AS parent_code, 'union' AS area_type, 'Narayanpur' AS name, 'BD-UNION-519' AS code
  UNION ALL
    SELECT 'BD-UPZ-56' AS parent_code, 'union' AS area_type, 'Upadi (South)' AS name, 'BD-UNION-520' AS code
  UNION ALL
    SELECT 'BD-UPZ-56' AS parent_code, 'union' AS area_type, 'Upadi (North)' AS name, 'BD-UNION-521' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Rajargaon (North)' AS name, 'BD-UNION-522' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Bakila' AS name, 'BD-UNION-523' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Kalocho (North)' AS name, 'BD-UNION-524' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Hajiganj Sadar' AS name, 'BD-UNION-525' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Kalocho (South)' AS name, 'BD-UNION-526' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Barkul (East)' AS name, 'BD-UNION-527' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Barkul (West)' AS name, 'BD-UNION-528' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Hatila (East)' AS name, 'BD-UNION-529' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Hatila (West)' AS name, 'BD-UNION-530' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Gandharbapur (North)' AS name, 'BD-UNION-531' AS code
  UNION ALL
    SELECT 'BD-UPZ-57' AS parent_code, 'union' AS area_type, 'Gandharbapur (South)' AS name, 'BD-UNION-532' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Satnal' AS name, 'BD-UNION-533' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Banganbari' AS name, 'BD-UNION-534' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Sadullapur' AS name, 'BD-UNION-535' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-536' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Kalakanda' AS name, 'BD-UNION-537' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Mohanpur' AS name, 'BD-UNION-538' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Eklaspur' AS name, 'BD-UNION-539' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Jahirabad' AS name, 'BD-UNION-540' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Fatehpur (East)' AS name, 'BD-UNION-541' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Fatehpur (West)' AS name, 'BD-UNION-542' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Farajikandi' AS name, 'BD-UNION-543' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Islamabad' AS name, 'BD-UNION-544' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Sultanabad' AS name, 'BD-UNION-545' AS code
  UNION ALL
    SELECT 'BD-UPZ-58' AS parent_code, 'union' AS area_type, 'Gazra' AS name, 'BD-UNION-546' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Balithuba (West)' AS name, 'BD-UNION-547' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Balithuba (East)' AS name, 'BD-UNION-548' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Subidpur (East)' AS name, 'BD-UNION-549' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Subidpur (West)' AS name, 'BD-UNION-550' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Gupti (West)' AS name, 'BD-UNION-551' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Gupti (East)' AS name, 'BD-UNION-552' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Paikpara (North)' AS name, 'BD-UNION-553' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Paikpara (South)' AS name, 'BD-UNION-554' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Gobindapur (North)' AS name, 'BD-UNION-555' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Gobindapur (South)' AS name, 'BD-UNION-556' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Chardukhia (East)' AS name, 'BD-UNION-557' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Chardukhia (West)' AS name, 'BD-UNION-558' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Faridgonj (South)' AS name, 'BD-UNION-559' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Rupsha (South)' AS name, 'BD-UNION-560' AS code
  UNION ALL
    SELECT 'BD-UPZ-59' AS parent_code, 'union' AS area_type, 'Rupsha (North)' AS name, 'BD-UNION-561' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Hamsadi (North)' AS name, 'BD-UNION-562' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Hamsadi (South)' AS name, 'BD-UNION-563' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Dalalbazar' AS name, 'BD-UNION-564' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Charruhita' AS name, 'BD-UNION-565' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Parbotinagar' AS name, 'BD-UNION-566' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Bangakha' AS name, 'BD-UNION-567' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Dattapara' AS name, 'BD-UNION-568' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Basikpur' AS name, 'BD-UNION-569' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Chandrogonj' AS name, 'BD-UNION-570' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Nourthjoypur' AS name, 'BD-UNION-571' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Hazirpara' AS name, 'BD-UNION-572' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Charshahi' AS name, 'BD-UNION-573' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Digli' AS name, 'BD-UNION-574' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Laharkandi' AS name, 'BD-UNION-575' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Vobanigonj' AS name, 'BD-UNION-576' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Kusakhali' AS name, 'BD-UNION-577' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Sakchor' AS name, 'BD-UNION-578' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Tearigonj' AS name, 'BD-UNION-579' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Tumchor' AS name, 'BD-UNION-580' AS code
  UNION ALL
    SELECT 'BD-UPZ-60' AS parent_code, 'union' AS area_type, 'Charramoni Mohon' AS name, 'BD-UNION-581' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Charkalkini' AS name, 'BD-UNION-582' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Shaheberhat' AS name, 'BD-UNION-583' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Char Martin' AS name, 'BD-UNION-584' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Char Folcon' AS name, 'BD-UNION-585' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Patarirhat' AS name, 'BD-UNION-586' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Hajirhat' AS name, 'BD-UNION-587' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Char Kadira' AS name, 'BD-UNION-588' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Torabgonj' AS name, 'BD-UNION-589' AS code
  UNION ALL
    SELECT 'BD-UPZ-61' AS parent_code, 'union' AS area_type, 'Charlorench' AS name, 'BD-UNION-590' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'North Char Ababil' AS name, 'BD-UNION-591' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'North Char Bangshi' AS name, 'BD-UNION-592' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'Char Mohana' AS name, 'BD-UNION-593' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'Sonapur' AS name, 'BD-UNION-594' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'Charpata' AS name, 'BD-UNION-595' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'Bamni' AS name, 'BD-UNION-596' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'South Char Bangshi' AS name, 'BD-UNION-597' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'South Char Ababil' AS name, 'BD-UNION-598' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'Raipur' AS name, 'BD-UNION-599' AS code
  UNION ALL
    SELECT 'BD-UPZ-62' AS parent_code, 'union' AS area_type, 'Keora' AS name, 'BD-UNION-600' AS code
  UNION ALL
    SELECT 'BD-UPZ-63' AS parent_code, 'union' AS area_type, 'Char Poragacha' AS name, 'BD-UNION-601' AS code
  UNION ALL
    SELECT 'BD-UPZ-63' AS parent_code, 'union' AS area_type, 'Charbadam' AS name, 'BD-UNION-602' AS code
  UNION ALL
    SELECT 'BD-UPZ-63' AS parent_code, 'union' AS area_type, 'Char Abdullah' AS name, 'BD-UNION-603' AS code
  UNION ALL
    SELECT 'BD-UPZ-63' AS parent_code, 'union' AS area_type, 'Alxendar' AS name, 'BD-UNION-604' AS code
  UNION ALL
    SELECT 'BD-UPZ-63' AS parent_code, 'union' AS area_type, 'Char Algi' AS name, 'BD-UNION-605' AS code
  UNION ALL
    SELECT 'BD-UPZ-63' AS parent_code, 'union' AS area_type, 'Char Ramiz' AS name, 'BD-UNION-606' AS code
  UNION ALL
    SELECT 'BD-UPZ-63' AS parent_code, 'union' AS area_type, 'Borokheri' AS name, 'BD-UNION-607' AS code
  UNION ALL
    SELECT 'BD-UPZ-63' AS parent_code, 'union' AS area_type, 'Chargazi' AS name, 'BD-UNION-608' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Kanchanpur' AS name, 'BD-UNION-609' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Noagaon' AS name, 'BD-UNION-610' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Bhadur' AS name, 'BD-UNION-611' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Ichhapur' AS name, 'BD-UNION-612' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Chandipur' AS name, 'BD-UNION-613' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Lamchar' AS name, 'BD-UNION-614' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Darbeshpur' AS name, 'BD-UNION-615' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Karpara' AS name, 'BD-UNION-616' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Bholakot' AS name, 'BD-UNION-617' AS code
  UNION ALL
    SELECT 'BD-UPZ-64' AS parent_code, 'union' AS area_type, 'Bhatra' AS name, 'BD-UNION-618' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Rajanagar' AS name, 'BD-UNION-619' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Hosnabad' AS name, 'BD-UNION-620' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Swanirbor Rangunia' AS name, 'BD-UNION-621' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Mariumnagar' AS name, 'BD-UNION-622' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Parua' AS name, 'BD-UNION-623' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Pomra' AS name, 'BD-UNION-624' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Betagi' AS name, 'BD-UNION-625' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Sharafbhata' AS name, 'BD-UNION-626' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Shilok' AS name, 'BD-UNION-627' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Chandraghona' AS name, 'BD-UNION-628' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Kodala' AS name, 'BD-UNION-629' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Islampur' AS name, 'BD-UNION-630' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'South Rajanagar' AS name, 'BD-UNION-631' AS code
  UNION ALL
    SELECT 'BD-UPZ-65' AS parent_code, 'union' AS area_type, 'Lalanagar' AS name, 'BD-UNION-632' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Kumira' AS name, 'BD-UNION-633' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Banshbaria' AS name, 'BD-UNION-634' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Barabkunda' AS name, 'BD-UNION-635' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Bariadyala' AS name, 'BD-UNION-636' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Muradpur' AS name, 'BD-UNION-637' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Saidpur' AS name, 'BD-UNION-638' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Salimpur' AS name, 'BD-UNION-639' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Sonaichhari' AS name, 'BD-UNION-640' AS code
  UNION ALL
    SELECT 'BD-UPZ-66' AS parent_code, 'union' AS area_type, 'Bhatiari' AS name, 'BD-UNION-641' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Korerhat' AS name, 'BD-UNION-642' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Hinguli' AS name, 'BD-UNION-643' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Jorarganj' AS name, 'BD-UNION-644' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Dhoom' AS name, 'BD-UNION-645' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Osmanpur' AS name, 'BD-UNION-646' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Ichakhali' AS name, 'BD-UNION-647' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Katachhara' AS name, 'BD-UNION-648' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-649' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Mirsharai' AS name, 'BD-UNION-650' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Mithanala' AS name, 'BD-UNION-651' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Maghadia' AS name, 'BD-UNION-652' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Khaiyachhara' AS name, 'BD-UNION-653' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Mayani' AS name, 'BD-UNION-654' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Haitkandi' AS name, 'BD-UNION-655' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Wahedpur' AS name, 'BD-UNION-656' AS code
  UNION ALL
    SELECT 'BD-UPZ-67' AS parent_code, 'union' AS area_type, 'Saherkhali' AS name, 'BD-UNION-657' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Asia' AS name, 'BD-UNION-658' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Kachuai' AS name, 'BD-UNION-659' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Kasiais' AS name, 'BD-UNION-660' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Kusumpura' AS name, 'BD-UNION-661' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Kelishahar' AS name, 'BD-UNION-662' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Kolagaon' AS name, 'BD-UNION-663' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Kharana' AS name, 'BD-UNION-664' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Char Patharghata' AS name, 'BD-UNION-665' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Char Lakshya' AS name, 'BD-UNION-666' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Chanhara' AS name, 'BD-UNION-667' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Janglukhain' AS name, 'BD-UNION-668' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Jiri' AS name, 'BD-UNION-669' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Juldha' AS name, 'BD-UNION-670' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Dakkhin Bhurshi' AS name, 'BD-UNION-671' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Dhalghat' AS name, 'BD-UNION-672' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Bara Uthan' AS name, 'BD-UNION-673' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Baralia' AS name, 'BD-UNION-674' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Bhatikhain' AS name, 'BD-UNION-675' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Sikalbaha' AS name, 'BD-UNION-676' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Sobhandandi' AS name, 'BD-UNION-677' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Habilasdwi' AS name, 'BD-UNION-678' AS code
  UNION ALL
    SELECT 'BD-UPZ-68' AS parent_code, 'union' AS area_type, 'Haidgaon' AS name, 'BD-UNION-679' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Rahmatpur' AS name, 'BD-UNION-680' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Harispur' AS name, 'BD-UNION-681' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Kalapania' AS name, 'BD-UNION-682' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Amanullah' AS name, 'BD-UNION-683' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Santoshpur' AS name, 'BD-UNION-684' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Gachhua' AS name, 'BD-UNION-685' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Bauria' AS name, 'BD-UNION-686' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Haramia' AS name, 'BD-UNION-687' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Magdhara' AS name, 'BD-UNION-688' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Maitbhanga' AS name, 'BD-UNION-689' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Sarikait' AS name, 'BD-UNION-690' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Musapur' AS name, 'BD-UNION-691' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Azimpur' AS name, 'BD-UNION-692' AS code
  UNION ALL
    SELECT 'BD-UPZ-69' AS parent_code, 'union' AS area_type, 'Urirchar' AS name, 'BD-UNION-693' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Pukuria' AS name, 'BD-UNION-694' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Sadhanpur' AS name, 'BD-UNION-695' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Khankhanabad' AS name, 'BD-UNION-696' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Baharchhara' AS name, 'BD-UNION-697' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Kalipur' AS name, 'BD-UNION-698' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Bailchhari' AS name, 'BD-UNION-699' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Katharia' AS name, 'BD-UNION-700' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Saral' AS name, 'BD-UNION-701' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Silk' AS name, 'BD-UNION-702' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Chambal' AS name, 'BD-UNION-703' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Gandamara' AS name, 'BD-UNION-704' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Sekherkhil' AS name, 'BD-UNION-705' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Puichhari' AS name, 'BD-UNION-706' AS code
  UNION ALL
    SELECT 'BD-UPZ-70' AS parent_code, 'union' AS area_type, 'Chhanua' AS name, 'BD-UNION-707' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Kandhurkhil' AS name, 'BD-UNION-708' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Pashchim Gamdandi' AS name, 'BD-UNION-709' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Purba Gomdandi' AS name, 'BD-UNION-710' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Sakpura' AS name, 'BD-UNION-711' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Saroatali' AS name, 'BD-UNION-712' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Popadia' AS name, 'BD-UNION-713' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Charandwi' AS name, 'BD-UNION-714' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Sreepur-Kharandwi' AS name, 'BD-UNION-715' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Amuchia' AS name, 'BD-UNION-716' AS code
  UNION ALL
    SELECT 'BD-UPZ-71' AS parent_code, 'union' AS area_type, 'Ahla Karaldenga' AS name, 'BD-UNION-717' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Boirag' AS name, 'BD-UNION-718' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Barasat' AS name, 'BD-UNION-719' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Raipur' AS name, 'BD-UNION-720' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Battali' AS name, 'BD-UNION-721' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Barumchara' AS name, 'BD-UNION-722' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Baroakhan' AS name, 'BD-UNION-723' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Anwara' AS name, 'BD-UNION-724' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Chatari' AS name, 'BD-UNION-725' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Paraikora' AS name, 'BD-UNION-726' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Haildhar' AS name, 'BD-UNION-727' AS code
  UNION ALL
    SELECT 'BD-UPZ-72' AS parent_code, 'union' AS area_type, 'Juidandi' AS name, 'BD-UNION-728' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Kanchanabad' AS name, 'BD-UNION-729' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Joara' AS name, 'BD-UNION-730' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Barkal' AS name, 'BD-UNION-731' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Barama' AS name, 'BD-UNION-732' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Bailtali' AS name, 'BD-UNION-733' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Satbaria' AS name, 'BD-UNION-734' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Hashimpur' AS name, 'BD-UNION-735' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Dohazari' AS name, 'BD-UNION-736' AS code
  UNION ALL
    SELECT 'BD-UPZ-73' AS parent_code, 'union' AS area_type, 'Dhopachhari' AS name, 'BD-UNION-737' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Charati' AS name, 'BD-UNION-738' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Khagaria' AS name, 'BD-UNION-739' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Nalua' AS name, 'BD-UNION-740' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Kanchana' AS name, 'BD-UNION-741' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Amilaisi' AS name, 'BD-UNION-742' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Eochiai' AS name, 'BD-UNION-743' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Madarsa' AS name, 'BD-UNION-744' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Dhemsa' AS name, 'BD-UNION-745' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Paschim Dhemsa' AS name, 'BD-UNION-746' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Keochia' AS name, 'BD-UNION-747' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Kaliais' AS name, 'BD-UNION-748' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Bazalia' AS name, 'BD-UNION-749' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Puranagar' AS name, 'BD-UNION-750' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Sadaha' AS name, 'BD-UNION-751' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Satkania' AS name, 'BD-UNION-752' AS code
  UNION ALL
    SELECT 'BD-UPZ-74' AS parent_code, 'union' AS area_type, 'Sonakania' AS name, 'BD-UNION-753' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Padua' AS name, 'BD-UNION-754' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Barahatia' AS name, 'BD-UNION-755' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Amirabad' AS name, 'BD-UNION-756' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Charamba' AS name, 'BD-UNION-757' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Kalauzan' AS name, 'BD-UNION-758' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Lohagara' AS name, 'BD-UNION-759' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Putibila' AS name, 'BD-UNION-760' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Chunati' AS name, 'BD-UNION-761' AS code
  UNION ALL
    SELECT 'BD-UPZ-75' AS parent_code, 'union' AS area_type, 'Adhunagar' AS name, 'BD-UNION-762' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Farhadabad' AS name, 'BD-UNION-763' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Dhalai' AS name, 'BD-UNION-764' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Mirjapur' AS name, 'BD-UNION-765' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Nangolmora' AS name, 'BD-UNION-766' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Gomanmordan' AS name, 'BD-UNION-767' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Chipatali' AS name, 'BD-UNION-768' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Mekhal' AS name, 'BD-UNION-769' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Garduara' AS name, 'BD-UNION-770' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Fathepur' AS name, 'BD-UNION-771' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Chikondandi' AS name, 'BD-UNION-772' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Uttar Madrasha' AS name, 'BD-UNION-773' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Dakkin Madrasha' AS name, 'BD-UNION-774' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Sikarpur' AS name, 'BD-UNION-775' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Budirchar' AS name, 'BD-UNION-776' AS code
  UNION ALL
    SELECT 'BD-UPZ-76' AS parent_code, 'union' AS area_type, 'Hathazari' AS name, 'BD-UNION-777' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Dharmapur' AS name, 'BD-UNION-778' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Baganbazar' AS name, 'BD-UNION-779' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Dantmara' AS name, 'BD-UNION-780' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Narayanhat' AS name, 'BD-UNION-781' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Bhujpur' AS name, 'BD-UNION-782' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Harualchari' AS name, 'BD-UNION-783' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Paindong' AS name, 'BD-UNION-784' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Kanchannagor' AS name, 'BD-UNION-785' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Sunderpur' AS name, 'BD-UNION-786' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Suabil' AS name, 'BD-UNION-787' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Abdullapur' AS name, 'BD-UNION-788' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Samitirhat' AS name, 'BD-UNION-789' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Jafathagar' AS name, 'BD-UNION-790' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Bokhtapur' AS name, 'BD-UNION-791' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Roshangiri' AS name, 'BD-UNION-792' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Nanupur' AS name, 'BD-UNION-793' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Lelang' AS name, 'BD-UNION-794' AS code
  UNION ALL
    SELECT 'BD-UPZ-77' AS parent_code, 'union' AS area_type, 'Daulatpur' AS name, 'BD-UNION-795' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Raozan' AS name, 'BD-UNION-796' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Bagoan' AS name, 'BD-UNION-797' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Binajuri' AS name, 'BD-UNION-798' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Chikdair' AS name, 'BD-UNION-799' AS code
  UNION ALL
    SELECT 'BD-UPZ-78' AS parent_code, 'union' AS area_type, 'Dabua' AS name, 'BD-UNION-800' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;