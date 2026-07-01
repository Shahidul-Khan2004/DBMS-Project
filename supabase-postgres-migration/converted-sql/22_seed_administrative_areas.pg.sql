-- Administrative areas: Bangladesh hierarchy (division → district → upazila → union)
-- Data source: https://github.com/nuhil/bangladesh-geocode (MIT). Codes are stable IDs from that dataset.
-- Bulk inserts (4 statements) for fast Docker init.

INSERT INTO administrative_areas (parent_area_id, area_type, name, code) VALUES
  (NULL, 'division', 'Chattagram', 'BD-DIV-1'),
  (NULL, 'division', 'Rajshahi', 'BD-DIV-2'),
  (NULL, 'division', 'Khulna', 'BD-DIV-3'),
  (NULL, 'division', 'Barisal', 'BD-DIV-4'),
  (NULL, 'division', 'Sylhet', 'BD-DIV-5'),
  (NULL, 'division', 'Dhaka', 'BD-DIV-6'),
  (NULL, 'division', 'Rangpur', 'BD-DIV-7'),
  (NULL, 'division', 'Mymensingh', 'BD-DIV-8')
 ON CONFLICT DO NOTHING;

INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Comilla' AS name, 'BD-DIST-1' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Feni' AS name, 'BD-DIST-2' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Brahmanbaria' AS name, 'BD-DIST-3' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Rangamati' AS name, 'BD-DIST-4' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Noakhali' AS name, 'BD-DIST-5' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Chandpur' AS name, 'BD-DIST-6' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Lakshmipur' AS name, 'BD-DIST-7' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Chattogram' AS name, 'BD-DIST-8' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Coxsbazar' AS name, 'BD-DIST-9' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Khagrachhari' AS name, 'BD-DIST-10' AS code
  UNION ALL
  SELECT 'BD-DIV-1' AS parent_code, 'district' AS area_type, 'Bandarban' AS name, 'BD-DIST-11' AS code
  UNION ALL
  SELECT 'BD-DIV-2' AS parent_code, 'district' AS area_type, 'Sirajganj' AS name, 'BD-DIST-12' AS code
  UNION ALL
  SELECT 'BD-DIV-2' AS parent_code, 'district' AS area_type, 'Pabna' AS name, 'BD-DIST-13' AS code
  UNION ALL
  SELECT 'BD-DIV-2' AS parent_code, 'district' AS area_type, 'Bogura' AS name, 'BD-DIST-14' AS code
  UNION ALL
  SELECT 'BD-DIV-2' AS parent_code, 'district' AS area_type, 'Rajshahi' AS name, 'BD-DIST-15' AS code
  UNION ALL
  SELECT 'BD-DIV-2' AS parent_code, 'district' AS area_type, 'Natore' AS name, 'BD-DIST-16' AS code
  UNION ALL
  SELECT 'BD-DIV-2' AS parent_code, 'district' AS area_type, 'Joypurhat' AS name, 'BD-DIST-17' AS code
  UNION ALL
  SELECT 'BD-DIV-2' AS parent_code, 'district' AS area_type, 'Chapainawabganj' AS name, 'BD-DIST-18' AS code
  UNION ALL
  SELECT 'BD-DIV-2' AS parent_code, 'district' AS area_type, 'Naogaon' AS name, 'BD-DIST-19' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Jashore' AS name, 'BD-DIST-20' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Satkhira' AS name, 'BD-DIST-21' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Meherpur' AS name, 'BD-DIST-22' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Narail' AS name, 'BD-DIST-23' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Chuadanga' AS name, 'BD-DIST-24' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Kushtia' AS name, 'BD-DIST-25' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Magura' AS name, 'BD-DIST-26' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Khulna' AS name, 'BD-DIST-27' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Bagerhat' AS name, 'BD-DIST-28' AS code
  UNION ALL
  SELECT 'BD-DIV-3' AS parent_code, 'district' AS area_type, 'Jhenaidah' AS name, 'BD-DIST-29' AS code
  UNION ALL
  SELECT 'BD-DIV-4' AS parent_code, 'district' AS area_type, 'Jhalakathi' AS name, 'BD-DIST-30' AS code
  UNION ALL
  SELECT 'BD-DIV-4' AS parent_code, 'district' AS area_type, 'Patuakhali' AS name, 'BD-DIST-31' AS code
  UNION ALL
  SELECT 'BD-DIV-4' AS parent_code, 'district' AS area_type, 'Pirojpur' AS name, 'BD-DIST-32' AS code
  UNION ALL
  SELECT 'BD-DIV-4' AS parent_code, 'district' AS area_type, 'Barisal' AS name, 'BD-DIST-33' AS code
  UNION ALL
  SELECT 'BD-DIV-4' AS parent_code, 'district' AS area_type, 'Bhola' AS name, 'BD-DIST-34' AS code
  UNION ALL
  SELECT 'BD-DIV-4' AS parent_code, 'district' AS area_type, 'Barguna' AS name, 'BD-DIST-35' AS code
  UNION ALL
  SELECT 'BD-DIV-5' AS parent_code, 'district' AS area_type, 'Sylhet' AS name, 'BD-DIST-36' AS code
  UNION ALL
  SELECT 'BD-DIV-5' AS parent_code, 'district' AS area_type, 'Moulvibazar' AS name, 'BD-DIST-37' AS code
  UNION ALL
  SELECT 'BD-DIV-5' AS parent_code, 'district' AS area_type, 'Habiganj' AS name, 'BD-DIST-38' AS code
  UNION ALL
  SELECT 'BD-DIV-5' AS parent_code, 'district' AS area_type, 'Sunamganj' AS name, 'BD-DIST-39' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Narsingdi' AS name, 'BD-DIST-40' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Gazipur' AS name, 'BD-DIST-41' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Shariatpur' AS name, 'BD-DIST-42' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Narayanganj' AS name, 'BD-DIST-43' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Tangail' AS name, 'BD-DIST-44' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Kishoreganj' AS name, 'BD-DIST-45' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Manikganj' AS name, 'BD-DIST-46' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Dhaka' AS name, 'BD-DIST-47' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Munshiganj' AS name, 'BD-DIST-48' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Rajbari' AS name, 'BD-DIST-49' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Madaripur' AS name, 'BD-DIST-50' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Gopalganj' AS name, 'BD-DIST-51' AS code
  UNION ALL
  SELECT 'BD-DIV-6' AS parent_code, 'district' AS area_type, 'Faridpur' AS name, 'BD-DIST-52' AS code
  UNION ALL
  SELECT 'BD-DIV-7' AS parent_code, 'district' AS area_type, 'Panchagarh' AS name, 'BD-DIST-53' AS code
  UNION ALL
  SELECT 'BD-DIV-7' AS parent_code, 'district' AS area_type, 'Dinajpur' AS name, 'BD-DIST-54' AS code
  UNION ALL
  SELECT 'BD-DIV-7' AS parent_code, 'district' AS area_type, 'Lalmonirhat' AS name, 'BD-DIST-55' AS code
  UNION ALL
  SELECT 'BD-DIV-7' AS parent_code, 'district' AS area_type, 'Nilphamari' AS name, 'BD-DIST-56' AS code
  UNION ALL
  SELECT 'BD-DIV-7' AS parent_code, 'district' AS area_type, 'Gaibandha' AS name, 'BD-DIST-57' AS code
  UNION ALL
  SELECT 'BD-DIV-7' AS parent_code, 'district' AS area_type, 'Thakurgaon' AS name, 'BD-DIST-58' AS code
  UNION ALL
  SELECT 'BD-DIV-7' AS parent_code, 'district' AS area_type, 'Rangpur' AS name, 'BD-DIST-59' AS code
  UNION ALL
  SELECT 'BD-DIV-7' AS parent_code, 'district' AS area_type, 'Kurigram' AS name, 'BD-DIST-60' AS code
  UNION ALL
  SELECT 'BD-DIV-8' AS parent_code, 'district' AS area_type, 'Sherpur' AS name, 'BD-DIST-61' AS code
  UNION ALL
  SELECT 'BD-DIV-8' AS parent_code, 'district' AS area_type, 'Mymensingh' AS name, 'BD-DIST-62' AS code
  UNION ALL
  SELECT 'BD-DIV-8' AS parent_code, 'district' AS area_type, 'Jamalpur' AS name, 'BD-DIST-63' AS code
  UNION ALL
  SELECT 'BD-DIV-8' AS parent_code, 'district' AS area_type, 'Netrokona' AS name, 'BD-DIST-64' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;

INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
  SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Debidwar' AS name, 'BD-UPZ-1' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Barura' AS name, 'BD-UPZ-2' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Brahmanpara' AS name, 'BD-UPZ-3' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Chandina' AS name, 'BD-UPZ-4' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Chauddagram' AS name, 'BD-UPZ-5' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Daudkandi' AS name, 'BD-UPZ-6' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Homna' AS name, 'BD-UPZ-7' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Laksam' AS name, 'BD-UPZ-8' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Muradnagar' AS name, 'BD-UPZ-9' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Nangalkot' AS name, 'BD-UPZ-10' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Comilla Sadar' AS name, 'BD-UPZ-11' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Meghna' AS name, 'BD-UPZ-12' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Monohargonj' AS name, 'BD-UPZ-13' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Sadarsouth' AS name, 'BD-UPZ-14' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Titas' AS name, 'BD-UPZ-15' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Burichang' AS name, 'BD-UPZ-16' AS code
  UNION ALL
    SELECT 'BD-DIST-1' AS parent_code, 'upazila' AS area_type, 'Lalmai' AS name, 'BD-UPZ-17' AS code
  UNION ALL
    SELECT 'BD-DIST-2' AS parent_code, 'upazila' AS area_type, 'Chhagalnaiya' AS name, 'BD-UPZ-18' AS code
  UNION ALL
    SELECT 'BD-DIST-2' AS parent_code, 'upazila' AS area_type, 'Feni Sadar' AS name, 'BD-UPZ-19' AS code
  UNION ALL
    SELECT 'BD-DIST-2' AS parent_code, 'upazila' AS area_type, 'Sonagazi' AS name, 'BD-UPZ-20' AS code
  UNION ALL
    SELECT 'BD-DIST-2' AS parent_code, 'upazila' AS area_type, 'Fulgazi' AS name, 'BD-UPZ-21' AS code
  UNION ALL
    SELECT 'BD-DIST-2' AS parent_code, 'upazila' AS area_type, 'Parshuram' AS name, 'BD-UPZ-22' AS code
  UNION ALL
    SELECT 'BD-DIST-2' AS parent_code, 'upazila' AS area_type, 'Daganbhuiyan' AS name, 'BD-UPZ-23' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Brahmanbaria Sadar' AS name, 'BD-UPZ-24' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Kasba' AS name, 'BD-UPZ-25' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Nasirnagar' AS name, 'BD-UPZ-26' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Sarail' AS name, 'BD-UPZ-27' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Ashuganj' AS name, 'BD-UPZ-28' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Akhaura' AS name, 'BD-UPZ-29' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Nabinagar' AS name, 'BD-UPZ-30' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Bancharampur' AS name, 'BD-UPZ-31' AS code
  UNION ALL
    SELECT 'BD-DIST-3' AS parent_code, 'upazila' AS area_type, 'Bijoynagar' AS name, 'BD-UPZ-32' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Rangamati Sadar' AS name, 'BD-UPZ-33' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Kaptai' AS name, 'BD-UPZ-34' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Kawkhali' AS name, 'BD-UPZ-35' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Baghaichari' AS name, 'BD-UPZ-36' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Barkal' AS name, 'BD-UPZ-37' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Langadu' AS name, 'BD-UPZ-38' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Rajasthali' AS name, 'BD-UPZ-39' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Belaichari' AS name, 'BD-UPZ-40' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Juraichari' AS name, 'BD-UPZ-41' AS code
  UNION ALL
    SELECT 'BD-DIST-4' AS parent_code, 'upazila' AS area_type, 'Naniarchar' AS name, 'BD-UPZ-42' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Noakhali Sadar' AS name, 'BD-UPZ-43' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Companiganj' AS name, 'BD-UPZ-44' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Begumganj' AS name, 'BD-UPZ-45' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Hatia' AS name, 'BD-UPZ-46' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Subarnachar' AS name, 'BD-UPZ-47' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Kabirhat' AS name, 'BD-UPZ-48' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Senbug' AS name, 'BD-UPZ-49' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Chatkhil' AS name, 'BD-UPZ-50' AS code
  UNION ALL
    SELECT 'BD-DIST-5' AS parent_code, 'upazila' AS area_type, 'Sonaimori' AS name, 'BD-UPZ-51' AS code
  UNION ALL
    SELECT 'BD-DIST-6' AS parent_code, 'upazila' AS area_type, 'Haimchar' AS name, 'BD-UPZ-52' AS code
  UNION ALL
    SELECT 'BD-DIST-6' AS parent_code, 'upazila' AS area_type, 'Kachua' AS name, 'BD-UPZ-53' AS code
  UNION ALL
    SELECT 'BD-DIST-6' AS parent_code, 'upazila' AS area_type, 'Shahrasti' AS name, 'BD-UPZ-54' AS code
  UNION ALL
    SELECT 'BD-DIST-6' AS parent_code, 'upazila' AS area_type, 'Chandpur Sadar' AS name, 'BD-UPZ-55' AS code
  UNION ALL
    SELECT 'BD-DIST-6' AS parent_code, 'upazila' AS area_type, 'Matlab South' AS name, 'BD-UPZ-56' AS code
  UNION ALL
    SELECT 'BD-DIST-6' AS parent_code, 'upazila' AS area_type, 'Hajiganj' AS name, 'BD-UPZ-57' AS code
  UNION ALL
    SELECT 'BD-DIST-6' AS parent_code, 'upazila' AS area_type, 'Matlab North' AS name, 'BD-UPZ-58' AS code
  UNION ALL
    SELECT 'BD-DIST-6' AS parent_code, 'upazila' AS area_type, 'Faridgonj' AS name, 'BD-UPZ-59' AS code
  UNION ALL
    SELECT 'BD-DIST-7' AS parent_code, 'upazila' AS area_type, 'Lakshmipur Sadar' AS name, 'BD-UPZ-60' AS code
  UNION ALL
    SELECT 'BD-DIST-7' AS parent_code, 'upazila' AS area_type, 'Kamalnagar' AS name, 'BD-UPZ-61' AS code
  UNION ALL
    SELECT 'BD-DIST-7' AS parent_code, 'upazila' AS area_type, 'Raipur' AS name, 'BD-UPZ-62' AS code
  UNION ALL
    SELECT 'BD-DIST-7' AS parent_code, 'upazila' AS area_type, 'Ramgati' AS name, 'BD-UPZ-63' AS code
  UNION ALL
    SELECT 'BD-DIST-7' AS parent_code, 'upazila' AS area_type, 'Ramganj' AS name, 'BD-UPZ-64' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Rangunia' AS name, 'BD-UPZ-65' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Sitakunda' AS name, 'BD-UPZ-66' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Mirsharai' AS name, 'BD-UPZ-67' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Patiya' AS name, 'BD-UPZ-68' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Sandwip' AS name, 'BD-UPZ-69' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Banshkhali' AS name, 'BD-UPZ-70' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Boalkhali' AS name, 'BD-UPZ-71' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Anwara' AS name, 'BD-UPZ-72' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Chandanaish' AS name, 'BD-UPZ-73' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Satkania' AS name, 'BD-UPZ-74' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Lohagara' AS name, 'BD-UPZ-75' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Hathazari' AS name, 'BD-UPZ-76' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Fatikchhari' AS name, 'BD-UPZ-77' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Raozan' AS name, 'BD-UPZ-78' AS code
  UNION ALL
    SELECT 'BD-DIST-8' AS parent_code, 'upazila' AS area_type, 'Karnafuli' AS name, 'BD-UPZ-79' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Coxsbazar Sadar' AS name, 'BD-UPZ-80' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Chakaria' AS name, 'BD-UPZ-81' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Kutubdia' AS name, 'BD-UPZ-82' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Ukhiya' AS name, 'BD-UPZ-83' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Moheshkhali' AS name, 'BD-UPZ-84' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Pekua' AS name, 'BD-UPZ-85' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Ramu' AS name, 'BD-UPZ-86' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Teknaf' AS name, 'BD-UPZ-87' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Khagrachhari Sadar' AS name, 'BD-UPZ-88' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Dighinala' AS name, 'BD-UPZ-89' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Panchari' AS name, 'BD-UPZ-90' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Laxmichhari' AS name, 'BD-UPZ-91' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Mohalchari' AS name, 'BD-UPZ-92' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Manikchari' AS name, 'BD-UPZ-93' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Ramgarh' AS name, 'BD-UPZ-94' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Matiranga' AS name, 'BD-UPZ-95' AS code
  UNION ALL
    SELECT 'BD-DIST-10' AS parent_code, 'upazila' AS area_type, 'Guimara' AS name, 'BD-UPZ-96' AS code
  UNION ALL
    SELECT 'BD-DIST-11' AS parent_code, 'upazila' AS area_type, 'Bandarban Sadar' AS name, 'BD-UPZ-97' AS code
  UNION ALL
    SELECT 'BD-DIST-11' AS parent_code, 'upazila' AS area_type, 'Alikadam' AS name, 'BD-UPZ-98' AS code
  UNION ALL
    SELECT 'BD-DIST-11' AS parent_code, 'upazila' AS area_type, 'Naikhongchhari' AS name, 'BD-UPZ-99' AS code
  UNION ALL
    SELECT 'BD-DIST-11' AS parent_code, 'upazila' AS area_type, 'Rowangchhari' AS name, 'BD-UPZ-100' AS code
  UNION ALL
    SELECT 'BD-DIST-11' AS parent_code, 'upazila' AS area_type, 'Lama' AS name, 'BD-UPZ-101' AS code
  UNION ALL
    SELECT 'BD-DIST-11' AS parent_code, 'upazila' AS area_type, 'Ruma' AS name, 'BD-UPZ-102' AS code
  UNION ALL
    SELECT 'BD-DIST-11' AS parent_code, 'upazila' AS area_type, 'Thanchi' AS name, 'BD-UPZ-103' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Belkuchi' AS name, 'BD-UPZ-104' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Chauhali' AS name, 'BD-UPZ-105' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Kamarkhand' AS name, 'BD-UPZ-106' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Kazipur' AS name, 'BD-UPZ-107' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Raigonj' AS name, 'BD-UPZ-108' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Shahjadpur' AS name, 'BD-UPZ-109' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Sirajganj Sadar' AS name, 'BD-UPZ-110' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Tarash' AS name, 'BD-UPZ-111' AS code
  UNION ALL
    SELECT 'BD-DIST-12' AS parent_code, 'upazila' AS area_type, 'Ullapara' AS name, 'BD-UPZ-112' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Sujanagar' AS name, 'BD-UPZ-113' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Ishurdi' AS name, 'BD-UPZ-114' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Bhangura' AS name, 'BD-UPZ-115' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Pabna Sadar' AS name, 'BD-UPZ-116' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Bera' AS name, 'BD-UPZ-117' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Atghoria' AS name, 'BD-UPZ-118' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Chatmohar' AS name, 'BD-UPZ-119' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Santhia' AS name, 'BD-UPZ-120' AS code
  UNION ALL
    SELECT 'BD-DIST-13' AS parent_code, 'upazila' AS area_type, 'Faridpur' AS name, 'BD-UPZ-121' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Kahaloo' AS name, 'BD-UPZ-122' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Bogra Sadar' AS name, 'BD-UPZ-123' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Shariakandi' AS name, 'BD-UPZ-124' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Shajahanpur' AS name, 'BD-UPZ-125' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Dupchanchia' AS name, 'BD-UPZ-126' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Adamdighi' AS name, 'BD-UPZ-127' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Nondigram' AS name, 'BD-UPZ-128' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Sonatala' AS name, 'BD-UPZ-129' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Dhunot' AS name, 'BD-UPZ-130' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Gabtali' AS name, 'BD-UPZ-131' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Sherpur' AS name, 'BD-UPZ-132' AS code
  UNION ALL
    SELECT 'BD-DIST-14' AS parent_code, 'upazila' AS area_type, 'Shibganj' AS name, 'BD-UPZ-133' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Paba' AS name, 'BD-UPZ-134' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Durgapur' AS name, 'BD-UPZ-135' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Mohonpur' AS name, 'BD-UPZ-136' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Charghat' AS name, 'BD-UPZ-137' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Puthia' AS name, 'BD-UPZ-138' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Bagha' AS name, 'BD-UPZ-139' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Godagari' AS name, 'BD-UPZ-140' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Tanore' AS name, 'BD-UPZ-141' AS code
  UNION ALL
    SELECT 'BD-DIST-15' AS parent_code, 'upazila' AS area_type, 'Bagmara' AS name, 'BD-UPZ-142' AS code
  UNION ALL
    SELECT 'BD-DIST-16' AS parent_code, 'upazila' AS area_type, 'Natore Sadar' AS name, 'BD-UPZ-143' AS code
  UNION ALL
    SELECT 'BD-DIST-16' AS parent_code, 'upazila' AS area_type, 'Singra' AS name, 'BD-UPZ-144' AS code
  UNION ALL
    SELECT 'BD-DIST-16' AS parent_code, 'upazila' AS area_type, 'Baraigram' AS name, 'BD-UPZ-145' AS code
  UNION ALL
    SELECT 'BD-DIST-16' AS parent_code, 'upazila' AS area_type, 'Bagatipara' AS name, 'BD-UPZ-146' AS code
  UNION ALL
    SELECT 'BD-DIST-16' AS parent_code, 'upazila' AS area_type, 'Lalpur' AS name, 'BD-UPZ-147' AS code
  UNION ALL
    SELECT 'BD-DIST-16' AS parent_code, 'upazila' AS area_type, 'Gurudaspur' AS name, 'BD-UPZ-148' AS code
  UNION ALL
    SELECT 'BD-DIST-16' AS parent_code, 'upazila' AS area_type, 'Naldanga' AS name, 'BD-UPZ-149' AS code
  UNION ALL
    SELECT 'BD-DIST-17' AS parent_code, 'upazila' AS area_type, 'Akkelpur' AS name, 'BD-UPZ-150' AS code
  UNION ALL
    SELECT 'BD-DIST-17' AS parent_code, 'upazila' AS area_type, 'Kalai' AS name, 'BD-UPZ-151' AS code
  UNION ALL
    SELECT 'BD-DIST-17' AS parent_code, 'upazila' AS area_type, 'Khetlal' AS name, 'BD-UPZ-152' AS code
  UNION ALL
    SELECT 'BD-DIST-17' AS parent_code, 'upazila' AS area_type, 'Panchbibi' AS name, 'BD-UPZ-153' AS code
  UNION ALL
    SELECT 'BD-DIST-17' AS parent_code, 'upazila' AS area_type, 'Joypurhat Sadar' AS name, 'BD-UPZ-154' AS code
  UNION ALL
    SELECT 'BD-DIST-18' AS parent_code, 'upazila' AS area_type, 'Chapainawabganj Sadar' AS name, 'BD-UPZ-155' AS code
  UNION ALL
    SELECT 'BD-DIST-18' AS parent_code, 'upazila' AS area_type, 'Gomostapur' AS name, 'BD-UPZ-156' AS code
  UNION ALL
    SELECT 'BD-DIST-18' AS parent_code, 'upazila' AS area_type, 'Nachol' AS name, 'BD-UPZ-157' AS code
  UNION ALL
    SELECT 'BD-DIST-18' AS parent_code, 'upazila' AS area_type, 'Bholahat' AS name, 'BD-UPZ-158' AS code
  UNION ALL
    SELECT 'BD-DIST-18' AS parent_code, 'upazila' AS area_type, 'Shibganj' AS name, 'BD-UPZ-159' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Mohadevpur' AS name, 'BD-UPZ-160' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Badalgachi' AS name, 'BD-UPZ-161' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Patnitala' AS name, 'BD-UPZ-162' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Dhamoirhat' AS name, 'BD-UPZ-163' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Niamatpur' AS name, 'BD-UPZ-164' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Manda' AS name, 'BD-UPZ-165' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Atrai' AS name, 'BD-UPZ-166' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Raninagar' AS name, 'BD-UPZ-167' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Naogaon Sadar' AS name, 'BD-UPZ-168' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Porsha' AS name, 'BD-UPZ-169' AS code
  UNION ALL
    SELECT 'BD-DIST-19' AS parent_code, 'upazila' AS area_type, 'Sapahar' AS name, 'BD-UPZ-170' AS code
  UNION ALL
    SELECT 'BD-DIST-20' AS parent_code, 'upazila' AS area_type, 'Manirampur' AS name, 'BD-UPZ-171' AS code
  UNION ALL
    SELECT 'BD-DIST-20' AS parent_code, 'upazila' AS area_type, 'Abhaynagar' AS name, 'BD-UPZ-172' AS code
  UNION ALL
    SELECT 'BD-DIST-20' AS parent_code, 'upazila' AS area_type, 'Bagherpara' AS name, 'BD-UPZ-173' AS code
  UNION ALL
    SELECT 'BD-DIST-20' AS parent_code, 'upazila' AS area_type, 'Chougachha' AS name, 'BD-UPZ-174' AS code
  UNION ALL
    SELECT 'BD-DIST-20' AS parent_code, 'upazila' AS area_type, 'Jhikargacha' AS name, 'BD-UPZ-175' AS code
  UNION ALL
    SELECT 'BD-DIST-20' AS parent_code, 'upazila' AS area_type, 'Keshabpur' AS name, 'BD-UPZ-176' AS code
  UNION ALL
    SELECT 'BD-DIST-20' AS parent_code, 'upazila' AS area_type, 'Jessore Sadar' AS name, 'BD-UPZ-177' AS code
  UNION ALL
    SELECT 'BD-DIST-20' AS parent_code, 'upazila' AS area_type, 'Sharsha' AS name, 'BD-UPZ-178' AS code
  UNION ALL
    SELECT 'BD-DIST-21' AS parent_code, 'upazila' AS area_type, 'Assasuni' AS name, 'BD-UPZ-179' AS code
  UNION ALL
    SELECT 'BD-DIST-21' AS parent_code, 'upazila' AS area_type, 'Debhata' AS name, 'BD-UPZ-180' AS code
  UNION ALL
    SELECT 'BD-DIST-21' AS parent_code, 'upazila' AS area_type, 'Kalaroa' AS name, 'BD-UPZ-181' AS code
  UNION ALL
    SELECT 'BD-DIST-21' AS parent_code, 'upazila' AS area_type, 'Satkhira Sadar' AS name, 'BD-UPZ-182' AS code
  UNION ALL
    SELECT 'BD-DIST-21' AS parent_code, 'upazila' AS area_type, 'Shyamnagar' AS name, 'BD-UPZ-183' AS code
  UNION ALL
    SELECT 'BD-DIST-21' AS parent_code, 'upazila' AS area_type, 'Tala' AS name, 'BD-UPZ-184' AS code
  UNION ALL
    SELECT 'BD-DIST-21' AS parent_code, 'upazila' AS area_type, 'Kaliganj' AS name, 'BD-UPZ-185' AS code
  UNION ALL
    SELECT 'BD-DIST-22' AS parent_code, 'upazila' AS area_type, 'Mujibnagar' AS name, 'BD-UPZ-186' AS code
  UNION ALL
    SELECT 'BD-DIST-22' AS parent_code, 'upazila' AS area_type, 'Meherpur Sadar' AS name, 'BD-UPZ-187' AS code
  UNION ALL
    SELECT 'BD-DIST-22' AS parent_code, 'upazila' AS area_type, 'Gangni' AS name, 'BD-UPZ-188' AS code
  UNION ALL
    SELECT 'BD-DIST-23' AS parent_code, 'upazila' AS area_type, 'Narail Sadar' AS name, 'BD-UPZ-189' AS code
  UNION ALL
    SELECT 'BD-DIST-23' AS parent_code, 'upazila' AS area_type, 'Lohagara' AS name, 'BD-UPZ-190' AS code
  UNION ALL
    SELECT 'BD-DIST-23' AS parent_code, 'upazila' AS area_type, 'Kalia' AS name, 'BD-UPZ-191' AS code
  UNION ALL
    SELECT 'BD-DIST-24' AS parent_code, 'upazila' AS area_type, 'Chuadanga Sadar' AS name, 'BD-UPZ-192' AS code
  UNION ALL
    SELECT 'BD-DIST-24' AS parent_code, 'upazila' AS area_type, 'Alamdanga' AS name, 'BD-UPZ-193' AS code
  UNION ALL
    SELECT 'BD-DIST-24' AS parent_code, 'upazila' AS area_type, 'Damurhuda' AS name, 'BD-UPZ-194' AS code
  UNION ALL
    SELECT 'BD-DIST-24' AS parent_code, 'upazila' AS area_type, 'Jibannagar' AS name, 'BD-UPZ-195' AS code
  UNION ALL
    SELECT 'BD-DIST-25' AS parent_code, 'upazila' AS area_type, 'Kushtia Sadar' AS name, 'BD-UPZ-196' AS code
  UNION ALL
    SELECT 'BD-DIST-25' AS parent_code, 'upazila' AS area_type, 'Kumarkhali' AS name, 'BD-UPZ-197' AS code
  UNION ALL
    SELECT 'BD-DIST-25' AS parent_code, 'upazila' AS area_type, 'Khoksa' AS name, 'BD-UPZ-198' AS code
  UNION ALL
    SELECT 'BD-DIST-25' AS parent_code, 'upazila' AS area_type, 'Mirpur' AS name, 'BD-UPZ-199' AS code
  UNION ALL
    SELECT 'BD-DIST-25' AS parent_code, 'upazila' AS area_type, 'Daulatpur' AS name, 'BD-UPZ-200' AS code
  UNION ALL
    SELECT 'BD-DIST-25' AS parent_code, 'upazila' AS area_type, 'Bheramara' AS name, 'BD-UPZ-201' AS code
  UNION ALL
    SELECT 'BD-DIST-26' AS parent_code, 'upazila' AS area_type, 'Shalikha' AS name, 'BD-UPZ-202' AS code
  UNION ALL
    SELECT 'BD-DIST-26' AS parent_code, 'upazila' AS area_type, 'Sreepur' AS name, 'BD-UPZ-203' AS code
  UNION ALL
    SELECT 'BD-DIST-26' AS parent_code, 'upazila' AS area_type, 'Magura Sadar' AS name, 'BD-UPZ-204' AS code
  UNION ALL
    SELECT 'BD-DIST-26' AS parent_code, 'upazila' AS area_type, 'Mohammadpur' AS name, 'BD-UPZ-205' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Paikgasa' AS name, 'BD-UPZ-206' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Fultola' AS name, 'BD-UPZ-207' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Digholia' AS name, 'BD-UPZ-208' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Rupsha' AS name, 'BD-UPZ-209' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Terokhada' AS name, 'BD-UPZ-210' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Dumuria' AS name, 'BD-UPZ-211' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Botiaghata' AS name, 'BD-UPZ-212' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Dakop' AS name, 'BD-UPZ-213' AS code
  UNION ALL
    SELECT 'BD-DIST-27' AS parent_code, 'upazila' AS area_type, 'Koyra' AS name, 'BD-UPZ-214' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Fakirhat' AS name, 'BD-UPZ-215' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Bagerhat Sadar' AS name, 'BD-UPZ-216' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Mollahat' AS name, 'BD-UPZ-217' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Sarankhola' AS name, 'BD-UPZ-218' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Rampal' AS name, 'BD-UPZ-219' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Morrelganj' AS name, 'BD-UPZ-220' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Kachua' AS name, 'BD-UPZ-221' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Mongla' AS name, 'BD-UPZ-222' AS code
  UNION ALL
    SELECT 'BD-DIST-28' AS parent_code, 'upazila' AS area_type, 'Chitalmari' AS name, 'BD-UPZ-223' AS code
  UNION ALL
    SELECT 'BD-DIST-29' AS parent_code, 'upazila' AS area_type, 'Jhenaidah Sadar' AS name, 'BD-UPZ-224' AS code
  UNION ALL
    SELECT 'BD-DIST-29' AS parent_code, 'upazila' AS area_type, 'Shailkupa' AS name, 'BD-UPZ-225' AS code
  UNION ALL
    SELECT 'BD-DIST-29' AS parent_code, 'upazila' AS area_type, 'Harinakundu' AS name, 'BD-UPZ-226' AS code
  UNION ALL
    SELECT 'BD-DIST-29' AS parent_code, 'upazila' AS area_type, 'Kaliganj' AS name, 'BD-UPZ-227' AS code
  UNION ALL
    SELECT 'BD-DIST-29' AS parent_code, 'upazila' AS area_type, 'Kotchandpur' AS name, 'BD-UPZ-228' AS code
  UNION ALL
    SELECT 'BD-DIST-29' AS parent_code, 'upazila' AS area_type, 'Moheshpur' AS name, 'BD-UPZ-229' AS code
  UNION ALL
    SELECT 'BD-DIST-30' AS parent_code, 'upazila' AS area_type, 'Jhalakathi Sadar' AS name, 'BD-UPZ-230' AS code
  UNION ALL
    SELECT 'BD-DIST-30' AS parent_code, 'upazila' AS area_type, 'Kathalia' AS name, 'BD-UPZ-231' AS code
  UNION ALL
    SELECT 'BD-DIST-30' AS parent_code, 'upazila' AS area_type, 'Nalchity' AS name, 'BD-UPZ-232' AS code
  UNION ALL
    SELECT 'BD-DIST-30' AS parent_code, 'upazila' AS area_type, 'Rajapur' AS name, 'BD-UPZ-233' AS code
  UNION ALL
    SELECT 'BD-DIST-31' AS parent_code, 'upazila' AS area_type, 'Bauphal' AS name, 'BD-UPZ-234' AS code
  UNION ALL
    SELECT 'BD-DIST-31' AS parent_code, 'upazila' AS area_type, 'Patuakhali Sadar' AS name, 'BD-UPZ-235' AS code
  UNION ALL
    SELECT 'BD-DIST-31' AS parent_code, 'upazila' AS area_type, 'Dumki' AS name, 'BD-UPZ-236' AS code
  UNION ALL
    SELECT 'BD-DIST-31' AS parent_code, 'upazila' AS area_type, 'Dashmina' AS name, 'BD-UPZ-237' AS code
  UNION ALL
    SELECT 'BD-DIST-31' AS parent_code, 'upazila' AS area_type, 'Kalapara' AS name, 'BD-UPZ-238' AS code
  UNION ALL
    SELECT 'BD-DIST-31' AS parent_code, 'upazila' AS area_type, 'Mirzaganj' AS name, 'BD-UPZ-239' AS code
  UNION ALL
    SELECT 'BD-DIST-31' AS parent_code, 'upazila' AS area_type, 'Galachipa' AS name, 'BD-UPZ-240' AS code
  UNION ALL
    SELECT 'BD-DIST-31' AS parent_code, 'upazila' AS area_type, 'Rangabali' AS name, 'BD-UPZ-241' AS code
  UNION ALL
    SELECT 'BD-DIST-32' AS parent_code, 'upazila' AS area_type, 'Pirojpur Sadar' AS name, 'BD-UPZ-242' AS code
  UNION ALL
    SELECT 'BD-DIST-32' AS parent_code, 'upazila' AS area_type, 'Nazirpur' AS name, 'BD-UPZ-243' AS code
  UNION ALL
    SELECT 'BD-DIST-32' AS parent_code, 'upazila' AS area_type, 'Kawkhali' AS name, 'BD-UPZ-244' AS code
  UNION ALL
    SELECT 'BD-DIST-32' AS parent_code, 'upazila' AS area_type, 'Zianagar' AS name, 'BD-UPZ-245' AS code
  UNION ALL
    SELECT 'BD-DIST-32' AS parent_code, 'upazila' AS area_type, 'Bhandaria' AS name, 'BD-UPZ-246' AS code
  UNION ALL
    SELECT 'BD-DIST-32' AS parent_code, 'upazila' AS area_type, 'Mathbaria' AS name, 'BD-UPZ-247' AS code
  UNION ALL
    SELECT 'BD-DIST-32' AS parent_code, 'upazila' AS area_type, 'Nesarabad' AS name, 'BD-UPZ-248' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Barisal Sadar' AS name, 'BD-UPZ-249' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Bakerganj' AS name, 'BD-UPZ-250' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Babuganj' AS name, 'BD-UPZ-251' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Wazirpur' AS name, 'BD-UPZ-252' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Banaripara' AS name, 'BD-UPZ-253' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Gournadi' AS name, 'BD-UPZ-254' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Agailjhara' AS name, 'BD-UPZ-255' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Mehendiganj' AS name, 'BD-UPZ-256' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Muladi' AS name, 'BD-UPZ-257' AS code
  UNION ALL
    SELECT 'BD-DIST-33' AS parent_code, 'upazila' AS area_type, 'Hizla' AS name, 'BD-UPZ-258' AS code
  UNION ALL
    SELECT 'BD-DIST-34' AS parent_code, 'upazila' AS area_type, 'Bhola Sadar' AS name, 'BD-UPZ-259' AS code
  UNION ALL
    SELECT 'BD-DIST-34' AS parent_code, 'upazila' AS area_type, 'Borhan Sddin' AS name, 'BD-UPZ-260' AS code
  UNION ALL
    SELECT 'BD-DIST-34' AS parent_code, 'upazila' AS area_type, 'Charfesson' AS name, 'BD-UPZ-261' AS code
  UNION ALL
    SELECT 'BD-DIST-34' AS parent_code, 'upazila' AS area_type, 'Doulatkhan' AS name, 'BD-UPZ-262' AS code
  UNION ALL
    SELECT 'BD-DIST-34' AS parent_code, 'upazila' AS area_type, 'Monpura' AS name, 'BD-UPZ-263' AS code
  UNION ALL
    SELECT 'BD-DIST-34' AS parent_code, 'upazila' AS area_type, 'Tazumuddin' AS name, 'BD-UPZ-264' AS code
  UNION ALL
    SELECT 'BD-DIST-34' AS parent_code, 'upazila' AS area_type, 'Lalmohan' AS name, 'BD-UPZ-265' AS code
  UNION ALL
    SELECT 'BD-DIST-35' AS parent_code, 'upazila' AS area_type, 'Amtali' AS name, 'BD-UPZ-266' AS code
  UNION ALL
    SELECT 'BD-DIST-35' AS parent_code, 'upazila' AS area_type, 'Barguna Sadar' AS name, 'BD-UPZ-267' AS code
  UNION ALL
    SELECT 'BD-DIST-35' AS parent_code, 'upazila' AS area_type, 'Betagi' AS name, 'BD-UPZ-268' AS code
  UNION ALL
    SELECT 'BD-DIST-35' AS parent_code, 'upazila' AS area_type, 'Bamna' AS name, 'BD-UPZ-269' AS code
  UNION ALL
    SELECT 'BD-DIST-35' AS parent_code, 'upazila' AS area_type, 'Pathorghata' AS name, 'BD-UPZ-270' AS code
  UNION ALL
    SELECT 'BD-DIST-35' AS parent_code, 'upazila' AS area_type, 'Taltali' AS name, 'BD-UPZ-271' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Balaganj' AS name, 'BD-UPZ-272' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Beanibazar' AS name, 'BD-UPZ-273' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Bishwanath' AS name, 'BD-UPZ-274' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Companiganj' AS name, 'BD-UPZ-275' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Fenchuganj' AS name, 'BD-UPZ-276' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Golapganj' AS name, 'BD-UPZ-277' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Gowainghat' AS name, 'BD-UPZ-278' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Jaintiapur' AS name, 'BD-UPZ-279' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Kanaighat' AS name, 'BD-UPZ-280' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Sylhet Sadar' AS name, 'BD-UPZ-281' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Zakiganj' AS name, 'BD-UPZ-282' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Dakshinsurma' AS name, 'BD-UPZ-283' AS code
  UNION ALL
    SELECT 'BD-DIST-36' AS parent_code, 'upazila' AS area_type, 'Osmaninagar' AS name, 'BD-UPZ-284' AS code
  UNION ALL
    SELECT 'BD-DIST-37' AS parent_code, 'upazila' AS area_type, 'Barlekha' AS name, 'BD-UPZ-285' AS code
  UNION ALL
    SELECT 'BD-DIST-37' AS parent_code, 'upazila' AS area_type, 'Kamolganj' AS name, 'BD-UPZ-286' AS code
  UNION ALL
    SELECT 'BD-DIST-37' AS parent_code, 'upazila' AS area_type, 'Kulaura' AS name, 'BD-UPZ-287' AS code
  UNION ALL
    SELECT 'BD-DIST-37' AS parent_code, 'upazila' AS area_type, 'Moulvibazar Sadar' AS name, 'BD-UPZ-288' AS code
  UNION ALL
    SELECT 'BD-DIST-37' AS parent_code, 'upazila' AS area_type, 'Rajnagar' AS name, 'BD-UPZ-289' AS code
  UNION ALL
    SELECT 'BD-DIST-37' AS parent_code, 'upazila' AS area_type, 'Sreemangal' AS name, 'BD-UPZ-290' AS code
  UNION ALL
    SELECT 'BD-DIST-37' AS parent_code, 'upazila' AS area_type, 'Juri' AS name, 'BD-UPZ-291' AS code
  UNION ALL
    SELECT 'BD-DIST-38' AS parent_code, 'upazila' AS area_type, 'Nabiganj' AS name, 'BD-UPZ-292' AS code
  UNION ALL
    SELECT 'BD-DIST-38' AS parent_code, 'upazila' AS area_type, 'Bahubal' AS name, 'BD-UPZ-293' AS code
  UNION ALL
    SELECT 'BD-DIST-38' AS parent_code, 'upazila' AS area_type, 'Ajmiriganj' AS name, 'BD-UPZ-294' AS code
  UNION ALL
    SELECT 'BD-DIST-38' AS parent_code, 'upazila' AS area_type, 'Baniachong' AS name, 'BD-UPZ-295' AS code
  UNION ALL
    SELECT 'BD-DIST-38' AS parent_code, 'upazila' AS area_type, 'Lakhai' AS name, 'BD-UPZ-296' AS code
  UNION ALL
    SELECT 'BD-DIST-38' AS parent_code, 'upazila' AS area_type, 'Chunarughat' AS name, 'BD-UPZ-297' AS code
  UNION ALL
    SELECT 'BD-DIST-38' AS parent_code, 'upazila' AS area_type, 'Habiganj Sadar' AS name, 'BD-UPZ-298' AS code
  UNION ALL
    SELECT 'BD-DIST-38' AS parent_code, 'upazila' AS area_type, 'Madhabpur' AS name, 'BD-UPZ-299' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Sunamganj Sadar' AS name, 'BD-UPZ-300' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'South Sunamganj' AS name, 'BD-UPZ-301' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Bishwambarpur' AS name, 'BD-UPZ-302' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Chhatak' AS name, 'BD-UPZ-303' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Jagannathpur' AS name, 'BD-UPZ-304' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Dowarabazar' AS name, 'BD-UPZ-305' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Tahirpur' AS name, 'BD-UPZ-306' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Dharmapasha' AS name, 'BD-UPZ-307' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Jamalganj' AS name, 'BD-UPZ-308' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Shalla' AS name, 'BD-UPZ-309' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Derai' AS name, 'BD-UPZ-310' AS code
  UNION ALL
    SELECT 'BD-DIST-40' AS parent_code, 'upazila' AS area_type, 'Belabo' AS name, 'BD-UPZ-311' AS code
  UNION ALL
    SELECT 'BD-DIST-40' AS parent_code, 'upazila' AS area_type, 'Monohardi' AS name, 'BD-UPZ-312' AS code
  UNION ALL
    SELECT 'BD-DIST-40' AS parent_code, 'upazila' AS area_type, 'Narsingdi Sadar' AS name, 'BD-UPZ-313' AS code
  UNION ALL
    SELECT 'BD-DIST-40' AS parent_code, 'upazila' AS area_type, 'Palash' AS name, 'BD-UPZ-314' AS code
  UNION ALL
    SELECT 'BD-DIST-40' AS parent_code, 'upazila' AS area_type, 'Raipura' AS name, 'BD-UPZ-315' AS code
  UNION ALL
    SELECT 'BD-DIST-40' AS parent_code, 'upazila' AS area_type, 'Shibpur' AS name, 'BD-UPZ-316' AS code
  UNION ALL
    SELECT 'BD-DIST-41' AS parent_code, 'upazila' AS area_type, 'Kaliganj' AS name, 'BD-UPZ-317' AS code
  UNION ALL
    SELECT 'BD-DIST-41' AS parent_code, 'upazila' AS area_type, 'Kaliakair' AS name, 'BD-UPZ-318' AS code
  UNION ALL
    SELECT 'BD-DIST-41' AS parent_code, 'upazila' AS area_type, 'Kapasia' AS name, 'BD-UPZ-319' AS code
  UNION ALL
    SELECT 'BD-DIST-41' AS parent_code, 'upazila' AS area_type, 'Gazipur Sadar' AS name, 'BD-UPZ-320' AS code
  UNION ALL
    SELECT 'BD-DIST-41' AS parent_code, 'upazila' AS area_type, 'Sreepur' AS name, 'BD-UPZ-321' AS code
  UNION ALL
    SELECT 'BD-DIST-42' AS parent_code, 'upazila' AS area_type, 'Shariatpur Sadar' AS name, 'BD-UPZ-322' AS code
  UNION ALL
    SELECT 'BD-DIST-42' AS parent_code, 'upazila' AS area_type, 'Naria' AS name, 'BD-UPZ-323' AS code
  UNION ALL
    SELECT 'BD-DIST-42' AS parent_code, 'upazila' AS area_type, 'Zajira' AS name, 'BD-UPZ-324' AS code
  UNION ALL
    SELECT 'BD-DIST-42' AS parent_code, 'upazila' AS area_type, 'Gosairhat' AS name, 'BD-UPZ-325' AS code
  UNION ALL
    SELECT 'BD-DIST-42' AS parent_code, 'upazila' AS area_type, 'Bhedarganj' AS name, 'BD-UPZ-326' AS code
  UNION ALL
    SELECT 'BD-DIST-42' AS parent_code, 'upazila' AS area_type, 'Damudya' AS name, 'BD-UPZ-327' AS code
  UNION ALL
    SELECT 'BD-DIST-43' AS parent_code, 'upazila' AS area_type, 'Araihazar' AS name, 'BD-UPZ-328' AS code
  UNION ALL
    SELECT 'BD-DIST-43' AS parent_code, 'upazila' AS area_type, 'Bandar' AS name, 'BD-UPZ-329' AS code
  UNION ALL
    SELECT 'BD-DIST-43' AS parent_code, 'upazila' AS area_type, 'Narayanganj Sadar' AS name, 'BD-UPZ-330' AS code
  UNION ALL
    SELECT 'BD-DIST-43' AS parent_code, 'upazila' AS area_type, 'Rupganj' AS name, 'BD-UPZ-331' AS code
  UNION ALL
    SELECT 'BD-DIST-43' AS parent_code, 'upazila' AS area_type, 'Sonargaon' AS name, 'BD-UPZ-332' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Basail' AS name, 'BD-UPZ-333' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Bhuapur' AS name, 'BD-UPZ-334' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Delduar' AS name, 'BD-UPZ-335' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Ghatail' AS name, 'BD-UPZ-336' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Gopalpur' AS name, 'BD-UPZ-337' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Madhupur' AS name, 'BD-UPZ-338' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Mirzapur' AS name, 'BD-UPZ-339' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Nagarpur' AS name, 'BD-UPZ-340' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Sakhipur' AS name, 'BD-UPZ-341' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Tangail Sadar' AS name, 'BD-UPZ-342' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Kalihati' AS name, 'BD-UPZ-343' AS code
  UNION ALL
    SELECT 'BD-DIST-44' AS parent_code, 'upazila' AS area_type, 'Dhanbari' AS name, 'BD-UPZ-344' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Itna' AS name, 'BD-UPZ-345' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Katiadi' AS name, 'BD-UPZ-346' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Bhairab' AS name, 'BD-UPZ-347' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Tarail' AS name, 'BD-UPZ-348' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Hossainpur' AS name, 'BD-UPZ-349' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Pakundia' AS name, 'BD-UPZ-350' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Kuliarchar' AS name, 'BD-UPZ-351' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Kishoreganj Sadar' AS name, 'BD-UPZ-352' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Karimgonj' AS name, 'BD-UPZ-353' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Bajitpur' AS name, 'BD-UPZ-354' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Austagram' AS name, 'BD-UPZ-355' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Mithamoin' AS name, 'BD-UPZ-356' AS code
  UNION ALL
    SELECT 'BD-DIST-45' AS parent_code, 'upazila' AS area_type, 'Nikli' AS name, 'BD-UPZ-357' AS code
  UNION ALL
    SELECT 'BD-DIST-46' AS parent_code, 'upazila' AS area_type, 'Harirampur' AS name, 'BD-UPZ-358' AS code
  UNION ALL
    SELECT 'BD-DIST-46' AS parent_code, 'upazila' AS area_type, 'Saturia' AS name, 'BD-UPZ-359' AS code
  UNION ALL
    SELECT 'BD-DIST-46' AS parent_code, 'upazila' AS area_type, 'Manikganj Sadar' AS name, 'BD-UPZ-360' AS code
  UNION ALL
    SELECT 'BD-DIST-46' AS parent_code, 'upazila' AS area_type, 'Gior' AS name, 'BD-UPZ-361' AS code
  UNION ALL
    SELECT 'BD-DIST-46' AS parent_code, 'upazila' AS area_type, 'Shibaloy' AS name, 'BD-UPZ-362' AS code
  UNION ALL
    SELECT 'BD-DIST-46' AS parent_code, 'upazila' AS area_type, 'Doulatpur' AS name, 'BD-UPZ-363' AS code
  UNION ALL
    SELECT 'BD-DIST-46' AS parent_code, 'upazila' AS area_type, 'Singiar' AS name, 'BD-UPZ-364' AS code
  UNION ALL
    SELECT 'BD-DIST-47' AS parent_code, 'upazila' AS area_type, 'Savar' AS name, 'BD-UPZ-365' AS code
  UNION ALL
    SELECT 'BD-DIST-47' AS parent_code, 'upazila' AS area_type, 'Dhamrai' AS name, 'BD-UPZ-366' AS code
  UNION ALL
    SELECT 'BD-DIST-47' AS parent_code, 'upazila' AS area_type, 'Keraniganj' AS name, 'BD-UPZ-367' AS code
  UNION ALL
    SELECT 'BD-DIST-47' AS parent_code, 'upazila' AS area_type, 'Nawabganj' AS name, 'BD-UPZ-368' AS code
  UNION ALL
    SELECT 'BD-DIST-47' AS parent_code, 'upazila' AS area_type, 'Dohar' AS name, 'BD-UPZ-369' AS code
  UNION ALL
    SELECT 'BD-DIST-48' AS parent_code, 'upazila' AS area_type, 'Munshiganj Sadar' AS name, 'BD-UPZ-370' AS code
  UNION ALL
    SELECT 'BD-DIST-48' AS parent_code, 'upazila' AS area_type, 'Sreenagar' AS name, 'BD-UPZ-371' AS code
  UNION ALL
    SELECT 'BD-DIST-48' AS parent_code, 'upazila' AS area_type, 'Sirajdikhan' AS name, 'BD-UPZ-372' AS code
  UNION ALL
    SELECT 'BD-DIST-48' AS parent_code, 'upazila' AS area_type, 'Louhajanj' AS name, 'BD-UPZ-373' AS code
  UNION ALL
    SELECT 'BD-DIST-48' AS parent_code, 'upazila' AS area_type, 'Gajaria' AS name, 'BD-UPZ-374' AS code
  UNION ALL
    SELECT 'BD-DIST-48' AS parent_code, 'upazila' AS area_type, 'Tongibari' AS name, 'BD-UPZ-375' AS code
  UNION ALL
    SELECT 'BD-DIST-49' AS parent_code, 'upazila' AS area_type, 'Rajbari Sadar' AS name, 'BD-UPZ-376' AS code
  UNION ALL
    SELECT 'BD-DIST-49' AS parent_code, 'upazila' AS area_type, 'Goalanda' AS name, 'BD-UPZ-377' AS code
  UNION ALL
    SELECT 'BD-DIST-49' AS parent_code, 'upazila' AS area_type, 'Pangsa' AS name, 'BD-UPZ-378' AS code
  UNION ALL
    SELECT 'BD-DIST-49' AS parent_code, 'upazila' AS area_type, 'Baliakandi' AS name, 'BD-UPZ-379' AS code
  UNION ALL
    SELECT 'BD-DIST-49' AS parent_code, 'upazila' AS area_type, 'Kalukhali' AS name, 'BD-UPZ-380' AS code
  UNION ALL
    SELECT 'BD-DIST-50' AS parent_code, 'upazila' AS area_type, 'Madaripur Sadar' AS name, 'BD-UPZ-381' AS code
  UNION ALL
    SELECT 'BD-DIST-50' AS parent_code, 'upazila' AS area_type, 'Shibchar' AS name, 'BD-UPZ-382' AS code
  UNION ALL
    SELECT 'BD-DIST-50' AS parent_code, 'upazila' AS area_type, 'Kalkini' AS name, 'BD-UPZ-383' AS code
  UNION ALL
    SELECT 'BD-DIST-50' AS parent_code, 'upazila' AS area_type, 'Rajoir' AS name, 'BD-UPZ-384' AS code
  UNION ALL
    SELECT 'BD-DIST-51' AS parent_code, 'upazila' AS area_type, 'Gopalganj Sadar' AS name, 'BD-UPZ-385' AS code
  UNION ALL
    SELECT 'BD-DIST-51' AS parent_code, 'upazila' AS area_type, 'Kashiani' AS name, 'BD-UPZ-386' AS code
  UNION ALL
    SELECT 'BD-DIST-51' AS parent_code, 'upazila' AS area_type, 'Tungipara' AS name, 'BD-UPZ-387' AS code
  UNION ALL
    SELECT 'BD-DIST-51' AS parent_code, 'upazila' AS area_type, 'Kotalipara' AS name, 'BD-UPZ-388' AS code
  UNION ALL
    SELECT 'BD-DIST-51' AS parent_code, 'upazila' AS area_type, 'Muksudpur' AS name, 'BD-UPZ-389' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Faridpur Sadar' AS name, 'BD-UPZ-390' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Alfadanga' AS name, 'BD-UPZ-391' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Boalmari' AS name, 'BD-UPZ-392' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Sadarpur' AS name, 'BD-UPZ-393' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Nagarkanda' AS name, 'BD-UPZ-394' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Bhanga' AS name, 'BD-UPZ-395' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Charbhadrasan' AS name, 'BD-UPZ-396' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Madhukhali' AS name, 'BD-UPZ-397' AS code
  UNION ALL
    SELECT 'BD-DIST-52' AS parent_code, 'upazila' AS area_type, 'Saltha' AS name, 'BD-UPZ-398' AS code
  UNION ALL
    SELECT 'BD-DIST-53' AS parent_code, 'upazila' AS area_type, 'Panchagarh Sadar' AS name, 'BD-UPZ-399' AS code
  UNION ALL
    SELECT 'BD-DIST-53' AS parent_code, 'upazila' AS area_type, 'Debiganj' AS name, 'BD-UPZ-400' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;

INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-DIST-53' AS parent_code, 'upazila' AS area_type, 'Boda' AS name, 'BD-UPZ-401' AS code
  UNION ALL
    SELECT 'BD-DIST-53' AS parent_code, 'upazila' AS area_type, 'Atwari' AS name, 'BD-UPZ-402' AS code
  UNION ALL
    SELECT 'BD-DIST-53' AS parent_code, 'upazila' AS area_type, 'Tetulia' AS name, 'BD-UPZ-403' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Nawabganj' AS name, 'BD-UPZ-404' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Birganj' AS name, 'BD-UPZ-405' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Ghoraghat' AS name, 'BD-UPZ-406' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Birampur' AS name, 'BD-UPZ-407' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Parbatipur' AS name, 'BD-UPZ-408' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Bochaganj' AS name, 'BD-UPZ-409' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Kaharol' AS name, 'BD-UPZ-410' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Fulbari' AS name, 'BD-UPZ-411' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Dinajpur Sadar' AS name, 'BD-UPZ-412' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Hakimpur' AS name, 'BD-UPZ-413' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Khansama' AS name, 'BD-UPZ-414' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Birol' AS name, 'BD-UPZ-415' AS code
  UNION ALL
    SELECT 'BD-DIST-54' AS parent_code, 'upazila' AS area_type, 'Chirirbandar' AS name, 'BD-UPZ-416' AS code
  UNION ALL
    SELECT 'BD-DIST-55' AS parent_code, 'upazila' AS area_type, 'Lalmonirhat Sadar' AS name, 'BD-UPZ-417' AS code
  UNION ALL
    SELECT 'BD-DIST-55' AS parent_code, 'upazila' AS area_type, 'Kaliganj' AS name, 'BD-UPZ-418' AS code
  UNION ALL
    SELECT 'BD-DIST-55' AS parent_code, 'upazila' AS area_type, 'Hatibandha' AS name, 'BD-UPZ-419' AS code
  UNION ALL
    SELECT 'BD-DIST-55' AS parent_code, 'upazila' AS area_type, 'Patgram' AS name, 'BD-UPZ-420' AS code
  UNION ALL
    SELECT 'BD-DIST-55' AS parent_code, 'upazila' AS area_type, 'Aditmari' AS name, 'BD-UPZ-421' AS code
  UNION ALL
    SELECT 'BD-DIST-56' AS parent_code, 'upazila' AS area_type, 'Syedpur' AS name, 'BD-UPZ-422' AS code
  UNION ALL
    SELECT 'BD-DIST-56' AS parent_code, 'upazila' AS area_type, 'Domar' AS name, 'BD-UPZ-423' AS code
  UNION ALL
    SELECT 'BD-DIST-56' AS parent_code, 'upazila' AS area_type, 'Dimla' AS name, 'BD-UPZ-424' AS code
  UNION ALL
    SELECT 'BD-DIST-56' AS parent_code, 'upazila' AS area_type, 'Jaldhaka' AS name, 'BD-UPZ-425' AS code
  UNION ALL
    SELECT 'BD-DIST-56' AS parent_code, 'upazila' AS area_type, 'Kishorganj' AS name, 'BD-UPZ-426' AS code
  UNION ALL
    SELECT 'BD-DIST-56' AS parent_code, 'upazila' AS area_type, 'Nilphamari Sadar' AS name, 'BD-UPZ-427' AS code
  UNION ALL
    SELECT 'BD-DIST-57' AS parent_code, 'upazila' AS area_type, 'Sadullapur' AS name, 'BD-UPZ-428' AS code
  UNION ALL
    SELECT 'BD-DIST-57' AS parent_code, 'upazila' AS area_type, 'Gaibandha Sadar' AS name, 'BD-UPZ-429' AS code
  UNION ALL
    SELECT 'BD-DIST-57' AS parent_code, 'upazila' AS area_type, 'Palashbari' AS name, 'BD-UPZ-430' AS code
  UNION ALL
    SELECT 'BD-DIST-57' AS parent_code, 'upazila' AS area_type, 'Saghata' AS name, 'BD-UPZ-431' AS code
  UNION ALL
    SELECT 'BD-DIST-57' AS parent_code, 'upazila' AS area_type, 'Gobindaganj' AS name, 'BD-UPZ-432' AS code
  UNION ALL
    SELECT 'BD-DIST-57' AS parent_code, 'upazila' AS area_type, 'Sundarganj' AS name, 'BD-UPZ-433' AS code
  UNION ALL
    SELECT 'BD-DIST-57' AS parent_code, 'upazila' AS area_type, 'Phulchari' AS name, 'BD-UPZ-434' AS code
  UNION ALL
    SELECT 'BD-DIST-58' AS parent_code, 'upazila' AS area_type, 'Thakurgaon Sadar' AS name, 'BD-UPZ-435' AS code
  UNION ALL
    SELECT 'BD-DIST-58' AS parent_code, 'upazila' AS area_type, 'Pirganj' AS name, 'BD-UPZ-436' AS code
  UNION ALL
    SELECT 'BD-DIST-58' AS parent_code, 'upazila' AS area_type, 'Ranisankail' AS name, 'BD-UPZ-437' AS code
  UNION ALL
    SELECT 'BD-DIST-58' AS parent_code, 'upazila' AS area_type, 'Haripur' AS name, 'BD-UPZ-438' AS code
  UNION ALL
    SELECT 'BD-DIST-58' AS parent_code, 'upazila' AS area_type, 'Baliadangi' AS name, 'BD-UPZ-439' AS code
  UNION ALL
    SELECT 'BD-DIST-59' AS parent_code, 'upazila' AS area_type, 'Rangpur Sadar' AS name, 'BD-UPZ-440' AS code
  UNION ALL
    SELECT 'BD-DIST-59' AS parent_code, 'upazila' AS area_type, 'Gangachara' AS name, 'BD-UPZ-441' AS code
  UNION ALL
    SELECT 'BD-DIST-59' AS parent_code, 'upazila' AS area_type, 'Taragonj' AS name, 'BD-UPZ-442' AS code
  UNION ALL
    SELECT 'BD-DIST-59' AS parent_code, 'upazila' AS area_type, 'Badargonj' AS name, 'BD-UPZ-443' AS code
  UNION ALL
    SELECT 'BD-DIST-59' AS parent_code, 'upazila' AS area_type, 'Mithapukur' AS name, 'BD-UPZ-444' AS code
  UNION ALL
    SELECT 'BD-DIST-59' AS parent_code, 'upazila' AS area_type, 'Pirgonj' AS name, 'BD-UPZ-445' AS code
  UNION ALL
    SELECT 'BD-DIST-59' AS parent_code, 'upazila' AS area_type, 'Kaunia' AS name, 'BD-UPZ-446' AS code
  UNION ALL
    SELECT 'BD-DIST-59' AS parent_code, 'upazila' AS area_type, 'Pirgacha' AS name, 'BD-UPZ-447' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Kurigram Sadar' AS name, 'BD-UPZ-448' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Nageshwari' AS name, 'BD-UPZ-449' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Bhurungamari' AS name, 'BD-UPZ-450' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Phulbari' AS name, 'BD-UPZ-451' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Rajarhat' AS name, 'BD-UPZ-452' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Ulipur' AS name, 'BD-UPZ-453' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Chilmari' AS name, 'BD-UPZ-454' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Rowmari' AS name, 'BD-UPZ-455' AS code
  UNION ALL
    SELECT 'BD-DIST-60' AS parent_code, 'upazila' AS area_type, 'Charrajibpur' AS name, 'BD-UPZ-456' AS code
  UNION ALL
    SELECT 'BD-DIST-61' AS parent_code, 'upazila' AS area_type, 'Sherpur Sadar' AS name, 'BD-UPZ-457' AS code
  UNION ALL
    SELECT 'BD-DIST-61' AS parent_code, 'upazila' AS area_type, 'Nalitabari' AS name, 'BD-UPZ-458' AS code
  UNION ALL
    SELECT 'BD-DIST-61' AS parent_code, 'upazila' AS area_type, 'Sreebordi' AS name, 'BD-UPZ-459' AS code
  UNION ALL
    SELECT 'BD-DIST-61' AS parent_code, 'upazila' AS area_type, 'Nokla' AS name, 'BD-UPZ-460' AS code
  UNION ALL
    SELECT 'BD-DIST-61' AS parent_code, 'upazila' AS area_type, 'Jhenaigati' AS name, 'BD-UPZ-461' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Fulbaria' AS name, 'BD-UPZ-462' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Trishal' AS name, 'BD-UPZ-463' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Bhaluka' AS name, 'BD-UPZ-464' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Muktagacha' AS name, 'BD-UPZ-465' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Mymensingh Sadar' AS name, 'BD-UPZ-466' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Dhobaura' AS name, 'BD-UPZ-467' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Phulpur' AS name, 'BD-UPZ-468' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Haluaghat' AS name, 'BD-UPZ-469' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Gouripur' AS name, 'BD-UPZ-470' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Gafargaon' AS name, 'BD-UPZ-471' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Iswarganj' AS name, 'BD-UPZ-472' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Nandail' AS name, 'BD-UPZ-473' AS code
  UNION ALL
    SELECT 'BD-DIST-62' AS parent_code, 'upazila' AS area_type, 'Tarakanda' AS name, 'BD-UPZ-474' AS code
  UNION ALL
    SELECT 'BD-DIST-63' AS parent_code, 'upazila' AS area_type, 'Jamalpur Sadar' AS name, 'BD-UPZ-475' AS code
  UNION ALL
    SELECT 'BD-DIST-63' AS parent_code, 'upazila' AS area_type, 'Melandah' AS name, 'BD-UPZ-476' AS code
  UNION ALL
    SELECT 'BD-DIST-63' AS parent_code, 'upazila' AS area_type, 'Islampur' AS name, 'BD-UPZ-477' AS code
  UNION ALL
    SELECT 'BD-DIST-63' AS parent_code, 'upazila' AS area_type, 'Dewangonj' AS name, 'BD-UPZ-478' AS code
  UNION ALL
    SELECT 'BD-DIST-63' AS parent_code, 'upazila' AS area_type, 'Sarishabari' AS name, 'BD-UPZ-479' AS code
  UNION ALL
    SELECT 'BD-DIST-63' AS parent_code, 'upazila' AS area_type, 'Madarganj' AS name, 'BD-UPZ-480' AS code
  UNION ALL
    SELECT 'BD-DIST-63' AS parent_code, 'upazila' AS area_type, 'Bokshiganj' AS name, 'BD-UPZ-481' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Barhatta' AS name, 'BD-UPZ-482' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Durgapur' AS name, 'BD-UPZ-483' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Kendua' AS name, 'BD-UPZ-484' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Atpara' AS name, 'BD-UPZ-485' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Madan' AS name, 'BD-UPZ-486' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Khaliajuri' AS name, 'BD-UPZ-487' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Kalmakanda' AS name, 'BD-UPZ-488' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Mohongonj' AS name, 'BD-UPZ-489' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Purbadhala' AS name, 'BD-UPZ-490' AS code
  UNION ALL
    SELECT 'BD-DIST-64' AS parent_code, 'upazila' AS area_type, 'Netrokona Sadar' AS name, 'BD-UPZ-491' AS code
  UNION ALL
    SELECT 'BD-DIST-9' AS parent_code, 'upazila' AS area_type, 'Eidgaon' AS name, 'BD-UPZ-492' AS code
  UNION ALL
    SELECT 'BD-DIST-39' AS parent_code, 'upazila' AS area_type, 'Madhyanagar' AS name, 'BD-UPZ-493' AS code
  UNION ALL
    SELECT 'BD-DIST-50' AS parent_code, 'upazila' AS area_type, 'Dasar' AS name, 'BD-UPZ-494' AS code

) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;

INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
  SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Subil' AS name, 'BD-UNION-1' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'North Gunaighor' AS name, 'BD-UNION-2' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'South Gunaighor' AS name, 'BD-UNION-3' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Boroshalghor' AS name, 'BD-UNION-4' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Rajameher' AS name, 'BD-UNION-5' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Yousufpur' AS name, 'BD-UNION-6' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Rasulpur' AS name, 'BD-UNION-7' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Fatehabad' AS name, 'BD-UNION-8' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Elahabad' AS name, 'BD-UNION-9' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Jafargonj' AS name, 'BD-UNION-10' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Dhampti' AS name, 'BD-UNION-11' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Mohanpur' AS name, 'BD-UNION-12' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Vani' AS name, 'BD-UNION-13' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Barkamta' AS name, 'BD-UNION-14' AS code
  UNION ALL
    SELECT 'BD-UPZ-1' AS parent_code, 'union' AS area_type, 'Sultanpur' AS name, 'BD-UNION-15' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Aganagar' AS name, 'BD-UNION-16' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Bhabanipur' AS name, 'BD-UNION-17' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'North Khoshbas' AS name, 'BD-UNION-18' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'South Khoshbas' AS name, 'BD-UNION-19' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Jhalam' AS name, 'BD-UNION-20' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Chitodda' AS name, 'BD-UNION-21' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'North Shilmuri' AS name, 'BD-UNION-22' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'South Shilmuri' AS name, 'BD-UNION-23' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Galimpur' AS name, 'BD-UNION-24' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Shakpur' AS name, 'BD-UNION-25' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Bhaukshar' AS name, 'BD-UNION-26' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Adda' AS name, 'BD-UNION-27' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Adra' AS name, 'BD-UNION-28' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Payalgacha' AS name, 'BD-UNION-29' AS code
  UNION ALL
    SELECT 'BD-UPZ-2' AS parent_code, 'union' AS area_type, 'Laxmipur' AS name, 'BD-UNION-30' AS code
  UNION ALL
    SELECT 'BD-UPZ-3' AS parent_code, 'union' AS area_type, 'Shidli' AS name, 'BD-UNION-31' AS code
  UNION ALL
    SELECT 'BD-UPZ-3' AS parent_code, 'union' AS area_type, 'Chandla' AS name, 'BD-UNION-32' AS code
  UNION ALL
    SELECT 'BD-UPZ-3' AS parent_code, 'union' AS area_type, 'Shashidal' AS name, 'BD-UNION-33' AS code
  UNION ALL
    SELECT 'BD-UPZ-3' AS parent_code, 'union' AS area_type, 'Dulalpur' AS name, 'BD-UNION-34' AS code
  UNION ALL
    SELECT 'BD-UPZ-3' AS parent_code, 'union' AS area_type, 'Brahmanpara Sadar' AS name, 'BD-UNION-35' AS code
  UNION ALL
    SELECT 'BD-UPZ-3' AS parent_code, 'union' AS area_type, 'Shahebabad' AS name, 'BD-UNION-36' AS code
  UNION ALL
    SELECT 'BD-UPZ-3' AS parent_code, 'union' AS area_type, 'Malapara' AS name, 'BD-UNION-37' AS code
  UNION ALL
    SELECT 'BD-UPZ-3' AS parent_code, 'union' AS area_type, 'Madhabpur' AS name, 'BD-UNION-38' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Shuhilpur' AS name, 'BD-UNION-39' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Bataghashi' AS name, 'BD-UNION-40' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Joag' AS name, 'BD-UNION-41' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Borcarai' AS name, 'BD-UNION-42' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Madhaiya' AS name, 'BD-UNION-43' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Dollai Nowabpur' AS name, 'BD-UNION-44' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Mohichial' AS name, 'BD-UNION-45' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Gollai' AS name, 'BD-UNION-46' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Keronkhal' AS name, 'BD-UNION-47' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Maijkhar' AS name, 'BD-UNION-48' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Etberpur' AS name, 'BD-UNION-49' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Barera' AS name, 'BD-UNION-50' AS code
  UNION ALL
    SELECT 'BD-UPZ-4' AS parent_code, 'union' AS area_type, 'Borcoit' AS name, 'BD-UNION-51' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Sreepur' AS name, 'BD-UNION-52' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Kashinagar' AS name, 'BD-UNION-53' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Kalikapur' AS name, 'BD-UNION-54' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Shuvapur' AS name, 'BD-UNION-55' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Ghulpasha' AS name, 'BD-UNION-56' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Moonshirhat' AS name, 'BD-UNION-57' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Batisha' AS name, 'BD-UNION-58' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Kankapait' AS name, 'BD-UNION-59' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Cheora' AS name, 'BD-UNION-60' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Jagannatdighi' AS name, 'BD-UNION-61' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Goonabati' AS name, 'BD-UNION-62' AS code
  UNION ALL
    SELECT 'BD-UPZ-5' AS parent_code, 'union' AS area_type, 'Alkara' AS name, 'BD-UNION-63' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Doulotpur' AS name, 'BD-UNION-64' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Daudkandi' AS name, 'BD-UNION-65' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'North Eliotgonj' AS name, 'BD-UNION-66' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'South Eliotgonj' AS name, 'BD-UNION-67' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Zinglatoli' AS name, 'BD-UNION-68' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Sundolpur' AS name, 'BD-UNION-69' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Gouripur' AS name, 'BD-UNION-70' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'East Mohammadpur' AS name, 'BD-UNION-71' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'West Mohammadpur' AS name, 'BD-UNION-72' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Goalmari' AS name, 'BD-UNION-73' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Maruka' AS name, 'BD-UNION-74' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Betessor' AS name, 'BD-UNION-75' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Podua' AS name, 'BD-UNION-76' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'West Passgacia' AS name, 'BD-UNION-77' AS code
  UNION ALL
    SELECT 'BD-UPZ-6' AS parent_code, 'union' AS area_type, 'Baropara' AS name, 'BD-UNION-78' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Mathabanga' AS name, 'BD-UNION-79' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Gagutiea' AS name, 'BD-UNION-80' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Asadpur' AS name, 'BD-UNION-81' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Chanderchor' AS name, 'BD-UNION-82' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Vashania' AS name, 'BD-UNION-83' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Nilokhi' AS name, 'BD-UNION-84' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Garmora' AS name, 'BD-UNION-85' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Joypur' AS name, 'BD-UNION-86' AS code
  UNION ALL
    SELECT 'BD-UPZ-7' AS parent_code, 'union' AS area_type, 'Dulalpur' AS name, 'BD-UNION-87' AS code
  UNION ALL
    SELECT 'BD-UPZ-8' AS parent_code, 'union' AS area_type, 'Bakoi' AS name, 'BD-UNION-88' AS code
  UNION ALL
    SELECT 'BD-UPZ-8' AS parent_code, 'union' AS area_type, 'Mudafargonj' AS name, 'BD-UNION-89' AS code
  UNION ALL
    SELECT 'BD-UPZ-8' AS parent_code, 'union' AS area_type, 'Kandirpar' AS name, 'BD-UNION-90' AS code
  UNION ALL
    SELECT 'BD-UPZ-8' AS parent_code, 'union' AS area_type, 'Gobindapur' AS name, 'BD-UNION-91' AS code
  UNION ALL
    SELECT 'BD-UPZ-8' AS parent_code, 'union' AS area_type, 'Uttarda' AS name, 'BD-UNION-92' AS code
  UNION ALL
    SELECT 'BD-UPZ-8' AS parent_code, 'union' AS area_type, 'Laksam Purba' AS name, 'BD-UNION-93' AS code
  UNION ALL
    SELECT 'BD-UPZ-8' AS parent_code, 'union' AS area_type, 'Azgora' AS name, 'BD-UNION-94' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Sreekil' AS name, 'BD-UNION-95' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Akubpur' AS name, 'BD-UNION-96' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Andicot' AS name, 'BD-UNION-97' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Purbadair (East)' AS name, 'BD-UNION-98' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Purbadair (West)' AS name, 'BD-UNION-99' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Bangara (East)' AS name, 'BD-UNION-100' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Bangara (West)' AS name, 'BD-UNION-101' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Chapitala' AS name, 'BD-UNION-102' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Camalla' AS name, 'BD-UNION-103' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Jatrapur' AS name, 'BD-UNION-104' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Ramachandrapur (North)' AS name, 'BD-UNION-105' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Ramachandrapur (South)' AS name, 'BD-UNION-106' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Muradnagar Sadar' AS name, 'BD-UNION-107' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Nobipur (East)' AS name, 'BD-UNION-108' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Nobipur (West)' AS name, 'BD-UNION-109' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Damgar' AS name, 'BD-UNION-110' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Jahapur' AS name, 'BD-UNION-111' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Salikandi' AS name, 'BD-UNION-112' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Darura' AS name, 'BD-UNION-113' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Paharpur' AS name, 'BD-UNION-114' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Babutipara' AS name, 'BD-UNION-115' AS code
  UNION ALL
    SELECT 'BD-UPZ-9' AS parent_code, 'union' AS area_type, 'Tanki' AS name, 'BD-UNION-116' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Bangadda' AS name, 'BD-UNION-117' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Paria' AS name, 'BD-UNION-118' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Raykot' AS name, 'BD-UNION-119' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Mokara' AS name, 'BD-UNION-120' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Makrabpur' AS name, 'BD-UNION-121' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Heshakhal' AS name, 'BD-UNION-122' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Adra' AS name, 'BD-UNION-123' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Judda' AS name, 'BD-UNION-124' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Dhalua' AS name, 'BD-UNION-125' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Doulkha' AS name, 'BD-UNION-126' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Boxgonj' AS name, 'BD-UNION-127' AS code
  UNION ALL
    SELECT 'BD-UPZ-10' AS parent_code, 'union' AS area_type, 'Satbaria' AS name, 'BD-UNION-128' AS code
  UNION ALL
    SELECT 'BD-UPZ-11' AS parent_code, 'union' AS area_type, 'Kalirbazer' AS name, 'BD-UNION-129' AS code
  UNION ALL
    SELECT 'BD-UPZ-11' AS parent_code, 'union' AS area_type, 'North Durgapur' AS name, 'BD-UNION-130' AS code
  UNION ALL
    SELECT 'BD-UPZ-11' AS parent_code, 'union' AS area_type, 'South Durgapur' AS name, 'BD-UNION-131' AS code
  UNION ALL
    SELECT 'BD-UPZ-11' AS parent_code, 'union' AS area_type, 'Amratoli' AS name, 'BD-UNION-132' AS code
  UNION ALL
    SELECT 'BD-UPZ-11' AS parent_code, 'union' AS area_type, 'Panchthubi' AS name, 'BD-UNION-133' AS code
  UNION ALL
    SELECT 'BD-UPZ-11' AS parent_code, 'union' AS area_type, 'Jagannatpur' AS name, 'BD-UNION-134' AS code
  UNION ALL
    SELECT 'BD-UPZ-12' AS parent_code, 'union' AS area_type, 'Chandanpur' AS name, 'BD-UNION-135' AS code
  UNION ALL
    SELECT 'BD-UPZ-12' AS parent_code, 'union' AS area_type, 'Chalibanga' AS name, 'BD-UNION-136' AS code
  UNION ALL
    SELECT 'BD-UPZ-12' AS parent_code, 'union' AS area_type, 'Radanagar' AS name, 'BD-UNION-137' AS code
  UNION ALL
    SELECT 'BD-UPZ-12' AS parent_code, 'union' AS area_type, 'Manikarchar' AS name, 'BD-UNION-138' AS code
  UNION ALL
    SELECT 'BD-UPZ-12' AS parent_code, 'union' AS area_type, 'Barakanda' AS name, 'BD-UNION-139' AS code
  UNION ALL
    SELECT 'BD-UPZ-12' AS parent_code, 'union' AS area_type, 'Govindapur' AS name, 'BD-UNION-140' AS code
  UNION ALL
    SELECT 'BD-UPZ-12' AS parent_code, 'union' AS area_type, 'Luterchar' AS name, 'BD-UNION-141' AS code
  UNION ALL
    SELECT 'BD-UPZ-12' AS parent_code, 'union' AS area_type, 'Vaorkhola' AS name, 'BD-UNION-142' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Baishgaon' AS name, 'BD-UNION-143' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Shoroshpur' AS name, 'BD-UNION-144' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Hasnabad' AS name, 'BD-UNION-145' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Jholam (North)' AS name, 'BD-UNION-146' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Jholam (South)' AS name, 'BD-UNION-147' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Moishatua' AS name, 'BD-UNION-148' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Lokkhanpur' AS name, 'BD-UNION-149' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Khela' AS name, 'BD-UNION-150' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Uttarhowla' AS name, 'BD-UNION-151' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Natherpetua' AS name, 'BD-UNION-152' AS code
  UNION ALL
    SELECT 'BD-UPZ-13' AS parent_code, 'union' AS area_type, 'Bipulashar' AS name, 'BD-UNION-153' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Chuwara' AS name, 'BD-UNION-154' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Baropara' AS name, 'BD-UNION-155' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Jorkanoneast' AS name, 'BD-UNION-156' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Goliara' AS name, 'BD-UNION-157' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Jorkanonwest' AS name, 'BD-UNION-158' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Bagmara (North)' AS name, 'BD-UNION-159' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Bagmara (South)' AS name, 'BD-UNION-160' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Bhuloin (North)' AS name, 'BD-UNION-161' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Bhuloin (South)' AS name, 'BD-UNION-162' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Belgor (North)' AS name, 'BD-UNION-163' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Belgor (South)' AS name, 'BD-UNION-164' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Perul (North)' AS name, 'BD-UNION-165' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Perul (South)' AS name, 'BD-UNION-166' AS code
  UNION ALL
    SELECT 'BD-UPZ-14' AS parent_code, 'union' AS area_type, 'Bijoypur' AS name, 'BD-UNION-167' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Satani' AS name, 'BD-UNION-168' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Jagatpur' AS name, 'BD-UNION-169' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Balorampur' AS name, 'BD-UNION-170' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Karikandi' AS name, 'BD-UNION-171' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Kalakandi' AS name, 'BD-UNION-172' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Vitikandi' AS name, 'BD-UNION-173' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Narayandia' AS name, 'BD-UNION-174' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Zearkandi' AS name, 'BD-UNION-175' AS code
  UNION ALL
    SELECT 'BD-UPZ-15' AS parent_code, 'union' AS area_type, 'Majidpur' AS name, 'BD-UNION-176' AS code
  UNION ALL
    SELECT 'BD-UPZ-16' AS parent_code, 'union' AS area_type, 'Moynamoti' AS name, 'BD-UNION-177' AS code
  UNION ALL
    SELECT 'BD-UPZ-16' AS parent_code, 'union' AS area_type, 'Varella' AS name, 'BD-UNION-178' AS code
  UNION ALL
    SELECT 'BD-UPZ-16' AS parent_code, 'union' AS area_type, 'Mokam' AS name, 'BD-UNION-179' AS code
  UNION ALL
    SELECT 'BD-UPZ-16' AS parent_code, 'union' AS area_type, 'Burichang Sadar' AS name, 'BD-UNION-180' AS code
  UNION ALL
    SELECT 'BD-UPZ-16' AS parent_code, 'union' AS area_type, 'Bakshimul' AS name, 'BD-UNION-181' AS code
  UNION ALL
    SELECT 'BD-UPZ-16' AS parent_code, 'union' AS area_type, 'Pirjatrapur' AS name, 'BD-UNION-182' AS code
  UNION ALL
    SELECT 'BD-UPZ-16' AS parent_code, 'union' AS area_type, 'Sholonal' AS name, 'BD-UNION-183' AS code
  UNION ALL
    SELECT 'BD-UPZ-16' AS parent_code, 'union' AS area_type, 'Rajapur' AS name, 'BD-UNION-184' AS code
  UNION ALL
    SELECT 'BD-UPZ-17' AS parent_code, 'union' AS area_type, 'Bagmara (North)' AS name, 'BD-UNION-185' AS code
  UNION ALL
    SELECT 'BD-UPZ-17' AS parent_code, 'union' AS area_type, 'Bagmara (South)' AS name, 'BD-UNION-186' AS code
  UNION ALL
    SELECT 'BD-UPZ-17' AS parent_code, 'union' AS area_type, 'Bhuloin (North)' AS name, 'BD-UNION-187' AS code
  UNION ALL
    SELECT 'BD-UPZ-17' AS parent_code, 'union' AS area_type, 'Bhuloin (South)' AS name, 'BD-UNION-188' AS code
  UNION ALL
    SELECT 'BD-UPZ-17' AS parent_code, 'union' AS area_type, 'Belgor (North)' AS name, 'BD-UNION-189' AS code
  UNION ALL
    SELECT 'BD-UPZ-17' AS parent_code, 'union' AS area_type, 'Belgor (South)' AS name, 'BD-UNION-190' AS code
  UNION ALL
    SELECT 'BD-UPZ-17' AS parent_code, 'union' AS area_type, 'Perul (North)' AS name, 'BD-UNION-191' AS code
  UNION ALL
    SELECT 'BD-UPZ-17' AS parent_code, 'union' AS area_type, 'Perul (South)' AS name, 'BD-UNION-192' AS code
  UNION ALL
    SELECT 'BD-UPZ-18' AS parent_code, 'union' AS area_type, 'Mohamaya' AS name, 'BD-UNION-193' AS code
  UNION ALL
    SELECT 'BD-UPZ-18' AS parent_code, 'union' AS area_type, 'Pathannagar' AS name, 'BD-UNION-194' AS code
  UNION ALL
    SELECT 'BD-UPZ-18' AS parent_code, 'union' AS area_type, 'Subhapur' AS name, 'BD-UNION-195' AS code
  UNION ALL
    SELECT 'BD-UPZ-18' AS parent_code, 'union' AS area_type, 'Radhanagar' AS name, 'BD-UNION-196' AS code
  UNION ALL
    SELECT 'BD-UPZ-18' AS parent_code, 'union' AS area_type, 'Gopal' AS name, 'BD-UNION-197' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Sarishadi' AS name, 'BD-UNION-198' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Panchgachia' AS name, 'BD-UNION-199' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Dhormapur' AS name, 'BD-UNION-200' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Kazirbag' AS name, 'BD-UNION-201' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Kalidah' AS name, 'BD-UNION-202' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Baligaon' AS name, 'BD-UNION-203' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Dholia' AS name, 'BD-UNION-204' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Lemua' AS name, 'BD-UNION-205' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Chonua' AS name, 'BD-UNION-206' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Motobi' AS name, 'BD-UNION-207' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Fazilpur' AS name, 'BD-UNION-208' AS code
  UNION ALL
    SELECT 'BD-UPZ-19' AS parent_code, 'union' AS area_type, 'Forhadnogor' AS name, 'BD-UNION-209' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Charmozlishpur' AS name, 'BD-UNION-210' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Bogadana' AS name, 'BD-UNION-211' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Motigonj' AS name, 'BD-UNION-212' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Mongolkandi' AS name, 'BD-UNION-213' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Chardorbesh' AS name, 'BD-UNION-214' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Chorchandia' AS name, 'BD-UNION-215' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Sonagazi' AS name, 'BD-UNION-216' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Amirabad' AS name, 'BD-UNION-217' AS code
  UNION ALL
    SELECT 'BD-UPZ-20' AS parent_code, 'union' AS area_type, 'Nababpur' AS name, 'BD-UNION-218' AS code
  UNION ALL
    SELECT 'BD-UPZ-21' AS parent_code, 'union' AS area_type, 'Fulgazi' AS name, 'BD-UNION-219' AS code
  UNION ALL
    SELECT 'BD-UPZ-21' AS parent_code, 'union' AS area_type, 'Munshirhat' AS name, 'BD-UNION-220' AS code
  UNION ALL
    SELECT 'BD-UPZ-21' AS parent_code, 'union' AS area_type, 'Dorbarpur' AS name, 'BD-UNION-221' AS code
  UNION ALL
    SELECT 'BD-UPZ-21' AS parent_code, 'union' AS area_type, 'Anandopur' AS name, 'BD-UNION-222' AS code
  UNION ALL
    SELECT 'BD-UPZ-21' AS parent_code, 'union' AS area_type, 'Amzadhat' AS name, 'BD-UNION-223' AS code
  UNION ALL
    SELECT 'BD-UPZ-21' AS parent_code, 'union' AS area_type, 'Gmhat' AS name, 'BD-UNION-224' AS code
  UNION ALL
    SELECT 'BD-UPZ-22' AS parent_code, 'union' AS area_type, 'Mizanagar' AS name, 'BD-UNION-225' AS code
  UNION ALL
    SELECT 'BD-UPZ-22' AS parent_code, 'union' AS area_type, 'Ctholia' AS name, 'BD-UNION-226' AS code
  UNION ALL
    SELECT 'BD-UPZ-22' AS parent_code, 'union' AS area_type, 'Boxmahmmud' AS name, 'BD-UNION-227' AS code
  UNION ALL
    SELECT 'BD-UPZ-23' AS parent_code, 'union' AS area_type, 'Sindurpur' AS name, 'BD-UNION-228' AS code
  UNION ALL
    SELECT 'BD-UPZ-23' AS parent_code, 'union' AS area_type, 'Rajapur' AS name, 'BD-UNION-229' AS code
  UNION ALL
    SELECT 'BD-UPZ-23' AS parent_code, 'union' AS area_type, 'Purbachandrapur' AS name, 'BD-UNION-230' AS code
  UNION ALL
    SELECT 'BD-UPZ-23' AS parent_code, 'union' AS area_type, 'Ramnagar' AS name, 'BD-UNION-231' AS code
  UNION ALL
    SELECT 'BD-UPZ-23' AS parent_code, 'union' AS area_type, 'Yeakubpur' AS name, 'BD-UNION-232' AS code
  UNION ALL
    SELECT 'BD-UPZ-23' AS parent_code, 'union' AS area_type, 'Daganbhuiyan' AS name, 'BD-UNION-233' AS code
  UNION ALL
    SELECT 'BD-UPZ-23' AS parent_code, 'union' AS area_type, 'Matubhuiyan' AS name, 'BD-UNION-234' AS code
  UNION ALL
    SELECT 'BD-UPZ-23' AS parent_code, 'union' AS area_type, 'Jayloskor' AS name, 'BD-UNION-235' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Basudeb' AS name, 'BD-UNION-236' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Machihata' AS name, 'BD-UNION-237' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Sultanpur' AS name, 'BD-UNION-238' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Ramrail' AS name, 'BD-UNION-239' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Sadekpur' AS name, 'BD-UNION-240' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Talsahar' AS name, 'BD-UNION-241' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Natai' AS name, 'BD-UNION-242' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Natai #243' AS name, 'BD-UNION-243' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Shuhilpur' AS name, 'BD-UNION-244' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Bodhal' AS name, 'BD-UNION-245' AS code
  UNION ALL
    SELECT 'BD-UPZ-24' AS parent_code, 'union' AS area_type, 'Majlishpur' AS name, 'BD-UNION-246' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Mulagram' AS name, 'BD-UNION-247' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Mehari' AS name, 'BD-UNION-248' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Badair' AS name, 'BD-UNION-249' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Kharera' AS name, 'BD-UNION-250' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Benauty' AS name, 'BD-UNION-251' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Gopinathpur' AS name, 'BD-UNION-252' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Kasbaw' AS name, 'BD-UNION-253' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Kuti' AS name, 'BD-UNION-254' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Kayempur' AS name, 'BD-UNION-255' AS code
  UNION ALL
    SELECT 'BD-UPZ-25' AS parent_code, 'union' AS area_type, 'Bayek' AS name, 'BD-UNION-256' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Chatalpar' AS name, 'BD-UNION-257' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Bhalakut' AS name, 'BD-UNION-258' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Kunda' AS name, 'BD-UNION-259' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Goalnagar' AS name, 'BD-UNION-260' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Nasirnagar' AS name, 'BD-UNION-261' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Burishwar' AS name, 'BD-UNION-262' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Fandauk' AS name, 'BD-UNION-263' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Goniauk' AS name, 'BD-UNION-264' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Chapartala' AS name, 'BD-UNION-265' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Dharnondol' AS name, 'BD-UNION-266' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Haripur' AS name, 'BD-UNION-267' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Purbabhag' AS name, 'BD-UNION-268' AS code
  UNION ALL
    SELECT 'BD-UPZ-26' AS parent_code, 'union' AS area_type, 'Gokarna' AS name, 'BD-UNION-269' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Auraol' AS name, 'BD-UNION-270' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Pakshimuul' AS name, 'BD-UNION-271' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Chunta' AS name, 'BD-UNION-272' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Kalikaccha' AS name, 'BD-UNION-273' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Panishor' AS name, 'BD-UNION-274' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Sarail' AS name, 'BD-UNION-275' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Noagoun' AS name, 'BD-UNION-276' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Shahajadapur' AS name, 'BD-UNION-277' AS code
  UNION ALL
    SELECT 'BD-UPZ-27' AS parent_code, 'union' AS area_type, 'Shahbazpur' AS name, 'BD-UNION-278' AS code
  UNION ALL
    SELECT 'BD-UPZ-28' AS parent_code, 'union' AS area_type, 'Ashuganj' AS name, 'BD-UNION-279' AS code
  UNION ALL
    SELECT 'BD-UPZ-28' AS parent_code, 'union' AS area_type, 'Charchartala' AS name, 'BD-UNION-280' AS code
  UNION ALL
    SELECT 'BD-UPZ-28' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-281' AS code
  UNION ALL
    SELECT 'BD-UPZ-28' AS parent_code, 'union' AS area_type, 'Araishidha' AS name, 'BD-UNION-282' AS code
  UNION ALL
    SELECT 'BD-UPZ-28' AS parent_code, 'union' AS area_type, 'Talshaharw' AS name, 'BD-UNION-283' AS code
  UNION ALL
    SELECT 'BD-UPZ-28' AS parent_code, 'union' AS area_type, 'Sarifpur' AS name, 'BD-UNION-284' AS code
  UNION ALL
    SELECT 'BD-UPZ-28' AS parent_code, 'union' AS area_type, 'Lalpur' AS name, 'BD-UNION-285' AS code
  UNION ALL
    SELECT 'BD-UPZ-28' AS parent_code, 'union' AS area_type, 'Tarua' AS name, 'BD-UNION-286' AS code
  UNION ALL
    SELECT 'BD-UPZ-29' AS parent_code, 'union' AS area_type, 'Monionda' AS name, 'BD-UNION-287' AS code
  UNION ALL
    SELECT 'BD-UPZ-29' AS parent_code, 'union' AS area_type, 'Dharkhar' AS name, 'BD-UNION-288' AS code
  UNION ALL
    SELECT 'BD-UPZ-29' AS parent_code, 'union' AS area_type, 'Mogra' AS name, 'BD-UNION-289' AS code
  UNION ALL
    SELECT 'BD-UPZ-29' AS parent_code, 'union' AS area_type, 'Akhauran' AS name, 'BD-UNION-290' AS code
  UNION ALL
    SELECT 'BD-UPZ-29' AS parent_code, 'union' AS area_type, 'Akhauras' AS name, 'BD-UNION-291' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Barail' AS name, 'BD-UNION-292' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Birgaon' AS name, 'BD-UNION-293' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Krishnanagar' AS name, 'BD-UNION-294' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Nathghar' AS name, 'BD-UNION-295' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Biddayakut' AS name, 'BD-UNION-296' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Nabinagare' AS name, 'BD-UNION-297' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Nabinagarw' AS name, 'BD-UNION-298' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Bitghar' AS name, 'BD-UNION-299' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Shibpur' AS name, 'BD-UNION-300' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Sreerampur' AS name, 'BD-UNION-301' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Jinudpur' AS name, 'BD-UNION-302' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Laurfatehpur' AS name, 'BD-UNION-303' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Ibrahimpur' AS name, 'BD-UNION-304' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Satmura' AS name, 'BD-UNION-305' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Shamogram' AS name, 'BD-UNION-306' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Rasullabad' AS name, 'BD-UNION-307' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Barikandi' AS name, 'BD-UNION-308' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Salimganj' AS name, 'BD-UNION-309' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Ratanpur' AS name, 'BD-UNION-310' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Kaitala (North)' AS name, 'BD-UNION-311' AS code
  UNION ALL
    SELECT 'BD-UPZ-30' AS parent_code, 'union' AS area_type, 'Kaitala (South)' AS name, 'BD-UNION-312' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Tazkhali' AS name, 'BD-UNION-313' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Pahariya Kandi' AS name, 'BD-UNION-314' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Dariadulat' AS name, 'BD-UNION-315' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Sonarampur' AS name, 'BD-UNION-316' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Darikandi' AS name, 'BD-UNION-317' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Saifullyakandi' AS name, 'BD-UNION-318' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Bancharampur' AS name, 'BD-UNION-319' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Ayabpur' AS name, 'BD-UNION-320' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Fardabad' AS name, 'BD-UNION-321' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Rupushdi' AS name, 'BD-UNION-322' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Salimabad' AS name, 'BD-UNION-323' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Ujanchar' AS name, 'BD-UNION-324' AS code
  UNION ALL
    SELECT 'BD-UPZ-31' AS parent_code, 'union' AS area_type, 'Manikpur' AS name, 'BD-UNION-325' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Bhudanty' AS name, 'BD-UNION-326' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Chandura' AS name, 'BD-UNION-327' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Ichapura' AS name, 'BD-UNION-328' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Champaknagar' AS name, 'BD-UNION-329' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Harashpur' AS name, 'BD-UNION-330' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Pattan' AS name, 'BD-UNION-331' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Singerbil' AS name, 'BD-UNION-332' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Bishupor' AS name, 'BD-UNION-333' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Charislampur' AS name, 'BD-UNION-334' AS code
  UNION ALL
    SELECT 'BD-UPZ-32' AS parent_code, 'union' AS area_type, 'Paharpur' AS name, 'BD-UNION-335' AS code
  UNION ALL
    SELECT 'BD-UPZ-33' AS parent_code, 'union' AS area_type, 'Jibtali' AS name, 'BD-UNION-336' AS code
  UNION ALL
    SELECT 'BD-UPZ-33' AS parent_code, 'union' AS area_type, 'Sapchari' AS name, 'BD-UNION-337' AS code
  UNION ALL
    SELECT 'BD-UPZ-33' AS parent_code, 'union' AS area_type, 'Kutukchari' AS name, 'BD-UNION-338' AS code
  UNION ALL
    SELECT 'BD-UPZ-33' AS parent_code, 'union' AS area_type, 'Bandukbhanga' AS name, 'BD-UNION-339' AS code
  UNION ALL
    SELECT 'BD-UPZ-33' AS parent_code, 'union' AS area_type, 'Balukhali' AS name, 'BD-UNION-340' AS code
  UNION ALL
    SELECT 'BD-UPZ-33' AS parent_code, 'union' AS area_type, 'Mogban' AS name, 'BD-UNION-341' AS code
  UNION ALL
    SELECT 'BD-UPZ-34' AS parent_code, 'union' AS area_type, 'Raikhali' AS name, 'BD-UNION-342' AS code
  UNION ALL
    SELECT 'BD-UPZ-34' AS parent_code, 'union' AS area_type, 'Kaptai' AS name, 'BD-UNION-343' AS code
  UNION ALL
    SELECT 'BD-UPZ-34' AS parent_code, 'union' AS area_type, 'Wagga' AS name, 'BD-UNION-344' AS code
  UNION ALL
    SELECT 'BD-UPZ-34' AS parent_code, 'union' AS area_type, 'Chandraghona' AS name, 'BD-UNION-345' AS code
  UNION ALL
    SELECT 'BD-UPZ-34' AS parent_code, 'union' AS area_type, 'Chitmorom' AS name, 'BD-UNION-346' AS code
  UNION ALL
    SELECT 'BD-UPZ-35' AS parent_code, 'union' AS area_type, 'Ghagra' AS name, 'BD-UNION-347' AS code
  UNION ALL
    SELECT 'BD-UPZ-35' AS parent_code, 'union' AS area_type, 'Fatikchari' AS name, 'BD-UNION-348' AS code
  UNION ALL
    SELECT 'BD-UPZ-35' AS parent_code, 'union' AS area_type, 'Betbunia' AS name, 'BD-UNION-349' AS code
  UNION ALL
    SELECT 'BD-UPZ-35' AS parent_code, 'union' AS area_type, 'Kalampati' AS name, 'BD-UNION-350' AS code
  UNION ALL
    SELECT 'BD-UPZ-36' AS parent_code, 'union' AS area_type, 'Sajek' AS name, 'BD-UNION-351' AS code
  UNION ALL
    SELECT 'BD-UPZ-36' AS parent_code, 'union' AS area_type, 'Amtali' AS name, 'BD-UNION-352' AS code
  UNION ALL
    SELECT 'BD-UPZ-36' AS parent_code, 'union' AS area_type, 'Bongoltali' AS name, 'BD-UNION-353' AS code
  UNION ALL
    SELECT 'BD-UPZ-36' AS parent_code, 'union' AS area_type, 'Rupokari' AS name, 'BD-UNION-354' AS code
  UNION ALL
    SELECT 'BD-UPZ-36' AS parent_code, 'union' AS area_type, 'Marisha' AS name, 'BD-UNION-355' AS code
  UNION ALL
    SELECT 'BD-UPZ-36' AS parent_code, 'union' AS area_type, 'Khedarmara' AS name, 'BD-UNION-356' AS code
  UNION ALL
    SELECT 'BD-UPZ-36' AS parent_code, 'union' AS area_type, 'Sharoyatali' AS name, 'BD-UNION-357' AS code
  UNION ALL
    SELECT 'BD-UPZ-36' AS parent_code, 'union' AS area_type, 'Baghaichari' AS name, 'BD-UNION-358' AS code
  UNION ALL
    SELECT 'BD-UPZ-37' AS parent_code, 'union' AS area_type, 'Subalong' AS name, 'BD-UNION-359' AS code
  UNION ALL
    SELECT 'BD-UPZ-37' AS parent_code, 'union' AS area_type, 'Barkal' AS name, 'BD-UNION-360' AS code
  UNION ALL
    SELECT 'BD-UPZ-37' AS parent_code, 'union' AS area_type, 'Bushanchara' AS name, 'BD-UNION-361' AS code
  UNION ALL
    SELECT 'BD-UPZ-37' AS parent_code, 'union' AS area_type, 'Aimachara' AS name, 'BD-UNION-362' AS code
  UNION ALL
    SELECT 'BD-UPZ-37' AS parent_code, 'union' AS area_type, 'Borohorina' AS name, 'BD-UNION-363' AS code
  UNION ALL
    SELECT 'BD-UPZ-38' AS parent_code, 'union' AS area_type, 'Langad' AS name, 'BD-UNION-364' AS code
  UNION ALL
    SELECT 'BD-UPZ-38' AS parent_code, 'union' AS area_type, 'Maeinimukh' AS name, 'BD-UNION-365' AS code
  UNION ALL
    SELECT 'BD-UPZ-38' AS parent_code, 'union' AS area_type, 'Vasannadam' AS name, 'BD-UNION-366' AS code
  UNION ALL
    SELECT 'BD-UPZ-38' AS parent_code, 'union' AS area_type, 'Bogachattar' AS name, 'BD-UNION-367' AS code
  UNION ALL
    SELECT 'BD-UPZ-38' AS parent_code, 'union' AS area_type, 'Gulshakhali' AS name, 'BD-UNION-368' AS code
  UNION ALL
    SELECT 'BD-UPZ-38' AS parent_code, 'union' AS area_type, 'Kalapakujja' AS name, 'BD-UNION-369' AS code
  UNION ALL
    SELECT 'BD-UPZ-38' AS parent_code, 'union' AS area_type, 'Atarakchara' AS name, 'BD-UNION-370' AS code
  UNION ALL
    SELECT 'BD-UPZ-39' AS parent_code, 'union' AS area_type, 'Ghilachari' AS name, 'BD-UNION-371' AS code
  UNION ALL
    SELECT 'BD-UPZ-39' AS parent_code, 'union' AS area_type, 'Gaindya' AS name, 'BD-UNION-372' AS code
  UNION ALL
    SELECT 'BD-UPZ-39' AS parent_code, 'union' AS area_type, 'Bangalhalia' AS name, 'BD-UNION-373' AS code
  UNION ALL
    SELECT 'BD-UPZ-40' AS parent_code, 'union' AS area_type, 'Kengrachari' AS name, 'BD-UNION-374' AS code
  UNION ALL
    SELECT 'BD-UPZ-40' AS parent_code, 'union' AS area_type, 'Belaichari' AS name, 'BD-UNION-375' AS code
  UNION ALL
    SELECT 'BD-UPZ-40' AS parent_code, 'union' AS area_type, 'Farua' AS name, 'BD-UNION-376' AS code
  UNION ALL
    SELECT 'BD-UPZ-41' AS parent_code, 'union' AS area_type, 'Juraichari' AS name, 'BD-UNION-377' AS code
  UNION ALL
    SELECT 'BD-UPZ-41' AS parent_code, 'union' AS area_type, 'Banajogichara' AS name, 'BD-UNION-378' AS code
  UNION ALL
    SELECT 'BD-UPZ-41' AS parent_code, 'union' AS area_type, 'Moidong' AS name, 'BD-UNION-379' AS code
  UNION ALL
    SELECT 'BD-UPZ-41' AS parent_code, 'union' AS area_type, 'Dumdumya' AS name, 'BD-UNION-380' AS code
  UNION ALL
    SELECT 'BD-UPZ-42' AS parent_code, 'union' AS area_type, 'Sabekkhong' AS name, 'BD-UNION-381' AS code
  UNION ALL
    SELECT 'BD-UPZ-42' AS parent_code, 'union' AS area_type, 'Naniarchar' AS name, 'BD-UNION-382' AS code
  UNION ALL
    SELECT 'BD-UPZ-42' AS parent_code, 'union' AS area_type, 'Burighat' AS name, 'BD-UNION-383' AS code
  UNION ALL
    SELECT 'BD-UPZ-42' AS parent_code, 'union' AS area_type, 'Ghilachhari' AS name, 'BD-UNION-384' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Charmatua' AS name, 'BD-UNION-385' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Dadpur' AS name, 'BD-UNION-386' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Noannoi' AS name, 'BD-UNION-387' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Kadirhanif' AS name, 'BD-UNION-388' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Binodpur' AS name, 'BD-UNION-389' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Dharmapur' AS name, 'BD-UNION-390' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Aujbalia' AS name, 'BD-UNION-391' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Kaladara' AS name, 'BD-UNION-392' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Ashwadia' AS name, 'BD-UNION-393' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Newajpur' AS name, 'BD-UNION-394' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'East Charmatua' AS name, 'BD-UNION-395' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Andarchar' AS name, 'BD-UNION-396' AS code
  UNION ALL
    SELECT 'BD-UPZ-43' AS parent_code, 'union' AS area_type, 'Noakhali' AS name, 'BD-UNION-397' AS code
  UNION ALL
    SELECT 'BD-UPZ-44' AS parent_code, 'union' AS area_type, 'Sirajpur' AS name, 'BD-UNION-398' AS code
  UNION ALL
    SELECT 'BD-UPZ-44' AS parent_code, 'union' AS area_type, 'Charparboti' AS name, 'BD-UNION-399' AS code
  UNION ALL
    SELECT 'BD-UPZ-44' AS parent_code, 'union' AS area_type, 'Charhazari' AS name, 'BD-UNION-400' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;

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

INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-132' AS parent_code, 'union' AS area_type, 'Bhabanipur' AS name, 'BD-UNION-1201' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Moidanhatta' AS name, 'BD-UNION-1202' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Kichok' AS name, 'BD-UNION-1203' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Atmul' AS name, 'BD-UNION-1204' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Pirob' AS name, 'BD-UNION-1205' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Majhihatta' AS name, 'BD-UNION-1206' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Buriganj' AS name, 'BD-UNION-1207' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Bihar' AS name, 'BD-UNION-1208' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Shibganj' AS name, 'BD-UNION-1209' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Deuly' AS name, 'BD-UNION-1210' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Sayedpur' AS name, 'BD-UNION-1211' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Mokamtala' AS name, 'BD-UNION-1212' AS code
  UNION ALL
    SELECT 'BD-UPZ-133' AS parent_code, 'union' AS area_type, 'Raynagar' AS name, 'BD-UNION-1213' AS code
  UNION ALL
    SELECT 'BD-UPZ-134' AS parent_code, 'union' AS area_type, 'Darsanpara' AS name, 'BD-UNION-1214' AS code
  UNION ALL
    SELECT 'BD-UPZ-134' AS parent_code, 'union' AS area_type, 'Hujuripara' AS name, 'BD-UNION-1215' AS code
  UNION ALL
    SELECT 'BD-UPZ-134' AS parent_code, 'union' AS area_type, 'Damkura' AS name, 'BD-UNION-1216' AS code
  UNION ALL
    SELECT 'BD-UPZ-134' AS parent_code, 'union' AS area_type, 'Horipur' AS name, 'BD-UNION-1217' AS code
  UNION ALL
    SELECT 'BD-UPZ-134' AS parent_code, 'union' AS area_type, 'Horogram' AS name, 'BD-UNION-1218' AS code
  UNION ALL
    SELECT 'BD-UPZ-134' AS parent_code, 'union' AS area_type, 'Harian' AS name, 'BD-UNION-1219' AS code
  UNION ALL
    SELECT 'BD-UPZ-134' AS parent_code, 'union' AS area_type, 'Borgachi' AS name, 'BD-UNION-1220' AS code
  UNION ALL
    SELECT 'BD-UPZ-134' AS parent_code, 'union' AS area_type, 'Parila' AS name, 'BD-UNION-1221' AS code
  UNION ALL
    SELECT 'BD-UPZ-135' AS parent_code, 'union' AS area_type, 'Naopara' AS name, 'BD-UNION-1222' AS code
  UNION ALL
    SELECT 'BD-UPZ-135' AS parent_code, 'union' AS area_type, 'Kismatgankoir' AS name, 'BD-UNION-1223' AS code
  UNION ALL
    SELECT 'BD-UPZ-135' AS parent_code, 'union' AS area_type, 'Pananagar' AS name, 'BD-UNION-1224' AS code
  UNION ALL
    SELECT 'BD-UPZ-135' AS parent_code, 'union' AS area_type, 'Deluabari' AS name, 'BD-UNION-1225' AS code
  UNION ALL
    SELECT 'BD-UPZ-135' AS parent_code, 'union' AS area_type, 'Jhaluka' AS name, 'BD-UNION-1226' AS code
  UNION ALL
    SELECT 'BD-UPZ-135' AS parent_code, 'union' AS area_type, 'Maria' AS name, 'BD-UNION-1227' AS code
  UNION ALL
    SELECT 'BD-UPZ-135' AS parent_code, 'union' AS area_type, 'Joynogor' AS name, 'BD-UNION-1228' AS code
  UNION ALL
    SELECT 'BD-UPZ-136' AS parent_code, 'union' AS area_type, 'Dhuroil' AS name, 'BD-UNION-1229' AS code
  UNION ALL
    SELECT 'BD-UPZ-136' AS parent_code, 'union' AS area_type, 'Ghasigram' AS name, 'BD-UNION-1230' AS code
  UNION ALL
    SELECT 'BD-UPZ-136' AS parent_code, 'union' AS area_type, 'Raighati' AS name, 'BD-UNION-1231' AS code
  UNION ALL
    SELECT 'BD-UPZ-136' AS parent_code, 'union' AS area_type, 'Mougachi' AS name, 'BD-UNION-1232' AS code
  UNION ALL
    SELECT 'BD-UPZ-136' AS parent_code, 'union' AS area_type, 'Baksimoil' AS name, 'BD-UNION-1233' AS code
  UNION ALL
    SELECT 'BD-UPZ-136' AS parent_code, 'union' AS area_type, 'Jahanabad' AS name, 'BD-UNION-1234' AS code
  UNION ALL
    SELECT 'BD-UPZ-137' AS parent_code, 'union' AS area_type, 'Yousufpur' AS name, 'BD-UNION-1235' AS code
  UNION ALL
    SELECT 'BD-UPZ-137' AS parent_code, 'union' AS area_type, 'Solua' AS name, 'BD-UNION-1236' AS code
  UNION ALL
    SELECT 'BD-UPZ-137' AS parent_code, 'union' AS area_type, 'Sardah' AS name, 'BD-UNION-1237' AS code
  UNION ALL
    SELECT 'BD-UPZ-137' AS parent_code, 'union' AS area_type, 'Nimpara' AS name, 'BD-UNION-1238' AS code
  UNION ALL
    SELECT 'BD-UPZ-137' AS parent_code, 'union' AS area_type, 'Charghat' AS name, 'BD-UNION-1239' AS code
  UNION ALL
    SELECT 'BD-UPZ-137' AS parent_code, 'union' AS area_type, 'Vialuxmipur' AS name, 'BD-UNION-1240' AS code
  UNION ALL
    SELECT 'BD-UPZ-138' AS parent_code, 'union' AS area_type, 'Puthia' AS name, 'BD-UNION-1241' AS code
  UNION ALL
    SELECT 'BD-UPZ-138' AS parent_code, 'union' AS area_type, 'Belpukuria' AS name, 'BD-UNION-1242' AS code
  UNION ALL
    SELECT 'BD-UPZ-138' AS parent_code, 'union' AS area_type, 'Baneswar' AS name, 'BD-UNION-1243' AS code
  UNION ALL
    SELECT 'BD-UPZ-138' AS parent_code, 'union' AS area_type, 'Valukgachi' AS name, 'BD-UNION-1244' AS code
  UNION ALL
    SELECT 'BD-UPZ-138' AS parent_code, 'union' AS area_type, 'Shilmaria' AS name, 'BD-UNION-1245' AS code
  UNION ALL
    SELECT 'BD-UPZ-138' AS parent_code, 'union' AS area_type, 'Jewpara' AS name, 'BD-UNION-1246' AS code
  UNION ALL
    SELECT 'BD-UPZ-139' AS parent_code, 'union' AS area_type, 'Bajubagha' AS name, 'BD-UNION-1247' AS code
  UNION ALL
    SELECT 'BD-UPZ-139' AS parent_code, 'union' AS area_type, 'Gorgori' AS name, 'BD-UNION-1248' AS code
  UNION ALL
    SELECT 'BD-UPZ-139' AS parent_code, 'union' AS area_type, 'Pakuria' AS name, 'BD-UNION-1249' AS code
  UNION ALL
    SELECT 'BD-UPZ-139' AS parent_code, 'union' AS area_type, 'Monigram' AS name, 'BD-UNION-1250' AS code
  UNION ALL
    SELECT 'BD-UPZ-139' AS parent_code, 'union' AS area_type, 'Bausa' AS name, 'BD-UNION-1251' AS code
  UNION ALL
    SELECT 'BD-UPZ-139' AS parent_code, 'union' AS area_type, 'Arani' AS name, 'BD-UNION-1252' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Godagari' AS name, 'BD-UNION-1253' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Mohonpur' AS name, 'BD-UNION-1254' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Pakri' AS name, 'BD-UNION-1255' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Risikul' AS name, 'BD-UNION-1256' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Gogram' AS name, 'BD-UNION-1257' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Matikata' AS name, 'BD-UNION-1258' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Dewpara' AS name, 'BD-UNION-1259' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Basudebpur' AS name, 'BD-UNION-1260' AS code
  UNION ALL
    SELECT 'BD-UPZ-140' AS parent_code, 'union' AS area_type, 'Asariadaha' AS name, 'BD-UNION-1261' AS code
  UNION ALL
    SELECT 'BD-UPZ-141' AS parent_code, 'union' AS area_type, 'Kalma' AS name, 'BD-UNION-1262' AS code
  UNION ALL
    SELECT 'BD-UPZ-141' AS parent_code, 'union' AS area_type, 'Badhair' AS name, 'BD-UNION-1263' AS code
  UNION ALL
    SELECT 'BD-UPZ-141' AS parent_code, 'union' AS area_type, 'Panchandar' AS name, 'BD-UNION-1264' AS code
  UNION ALL
    SELECT 'BD-UPZ-141' AS parent_code, 'union' AS area_type, 'Saranjai' AS name, 'BD-UNION-1265' AS code
  UNION ALL
    SELECT 'BD-UPZ-141' AS parent_code, 'union' AS area_type, 'Talondo' AS name, 'BD-UNION-1266' AS code
  UNION ALL
    SELECT 'BD-UPZ-141' AS parent_code, 'union' AS area_type, 'Kamargaon' AS name, 'BD-UNION-1267' AS code
  UNION ALL
    SELECT 'BD-UPZ-141' AS parent_code, 'union' AS area_type, 'Chanduria' AS name, 'BD-UNION-1268' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Gobindopara' AS name, 'BD-UNION-1269' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Nordas' AS name, 'BD-UNION-1270' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Dippur' AS name, 'BD-UNION-1271' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Borobihanoli' AS name, 'BD-UNION-1272' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Auchpara' AS name, 'BD-UNION-1273' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Sreepur' AS name, 'BD-UNION-1274' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Basupara' AS name, 'BD-UNION-1275' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Kacharikoalipara' AS name, 'BD-UNION-1276' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Suvodanga' AS name, 'BD-UNION-1277' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Mariaup' AS name, 'BD-UNION-1278' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Ganipur' AS name, 'BD-UNION-1279' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Zhikara' AS name, 'BD-UNION-1280' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Gualkandi' AS name, 'BD-UNION-1281' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Hamirkutsa' AS name, 'BD-UNION-1282' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Jogipara' AS name, 'BD-UNION-1283' AS code
  UNION ALL
    SELECT 'BD-UPZ-142' AS parent_code, 'union' AS area_type, 'Sonadanga' AS name, 'BD-UNION-1284' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Brahmapur' AS name, 'BD-UNION-1285' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Madhnagar' AS name, 'BD-UNION-1286' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Khajura' AS name, 'BD-UNION-1287' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Piprul' AS name, 'BD-UNION-1288' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Biprobelghoria' AS name, 'BD-UNION-1289' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Chhatni' AS name, 'BD-UNION-1290' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Tebaria' AS name, 'BD-UNION-1291' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Dighapatia' AS name, 'BD-UNION-1292' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Luxmipurkholabaria' AS name, 'BD-UNION-1293' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Barahorispur' AS name, 'BD-UNION-1294' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Kaphuria' AS name, 'BD-UNION-1295' AS code
  UNION ALL
    SELECT 'BD-UPZ-143' AS parent_code, 'union' AS area_type, 'Halsa' AS name, 'BD-UNION-1296' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Sukash' AS name, 'BD-UNION-1297' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Dahia' AS name, 'BD-UNION-1298' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Italy' AS name, 'BD-UNION-1299' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Kalam' AS name, 'BD-UNION-1300' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Chamari' AS name, 'BD-UNION-1301' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Hatiandaha' AS name, 'BD-UNION-1302' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Lalore' AS name, 'BD-UNION-1303' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Sherkole' AS name, 'BD-UNION-1304' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Tajpur' AS name, 'BD-UNION-1305' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Chaugram' AS name, 'BD-UNION-1306' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Chhatardighi' AS name, 'BD-UNION-1307' AS code
  UNION ALL
    SELECT 'BD-UPZ-144' AS parent_code, 'union' AS area_type, 'Ramanandakhajura' AS name, 'BD-UNION-1308' AS code
  UNION ALL
    SELECT 'BD-UPZ-145' AS parent_code, 'union' AS area_type, 'Joari' AS name, 'BD-UNION-1309' AS code
  UNION ALL
    SELECT 'BD-UPZ-145' AS parent_code, 'union' AS area_type, 'Baraigram' AS name, 'BD-UNION-1310' AS code
  UNION ALL
    SELECT 'BD-UPZ-145' AS parent_code, 'union' AS area_type, 'Zonail' AS name, 'BD-UNION-1311' AS code
  UNION ALL
    SELECT 'BD-UPZ-145' AS parent_code, 'union' AS area_type, 'Nagor' AS name, 'BD-UNION-1312' AS code
  UNION ALL
    SELECT 'BD-UPZ-145' AS parent_code, 'union' AS area_type, 'Majgoan' AS name, 'BD-UNION-1313' AS code
  UNION ALL
    SELECT 'BD-UPZ-145' AS parent_code, 'union' AS area_type, 'Gopalpur' AS name, 'BD-UNION-1314' AS code
  UNION ALL
    SELECT 'BD-UPZ-145' AS parent_code, 'union' AS area_type, 'Chandai' AS name, 'BD-UNION-1315' AS code
  UNION ALL
    SELECT 'BD-UPZ-146' AS parent_code, 'union' AS area_type, 'Panka' AS name, 'BD-UNION-1316' AS code
  UNION ALL
    SELECT 'BD-UPZ-146' AS parent_code, 'union' AS area_type, 'Jamnagor' AS name, 'BD-UNION-1317' AS code
  UNION ALL
    SELECT 'BD-UPZ-146' AS parent_code, 'union' AS area_type, 'Bagatipara' AS name, 'BD-UNION-1318' AS code
  UNION ALL
    SELECT 'BD-UPZ-146' AS parent_code, 'union' AS area_type, 'Dayarampur' AS name, 'BD-UNION-1319' AS code
  UNION ALL
    SELECT 'BD-UPZ-146' AS parent_code, 'union' AS area_type, 'Faguardiar' AS name, 'BD-UNION-1320' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Lalpur' AS name, 'BD-UNION-1321' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Iswardi' AS name, 'BD-UNION-1322' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Chongdhupoil' AS name, 'BD-UNION-1323' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Arbab' AS name, 'BD-UNION-1324' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Bilmaria' AS name, 'BD-UNION-1325' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Duaria' AS name, 'BD-UNION-1326' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Oalia' AS name, 'BD-UNION-1327' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Durduria' AS name, 'BD-UNION-1328' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Arjunpur' AS name, 'BD-UNION-1329' AS code
  UNION ALL
    SELECT 'BD-UPZ-147' AS parent_code, 'union' AS area_type, 'Kadimchilan' AS name, 'BD-UNION-1330' AS code
  UNION ALL
    SELECT 'BD-UPZ-148' AS parent_code, 'union' AS area_type, 'Nazirpur' AS name, 'BD-UNION-1331' AS code
  UNION ALL
    SELECT 'BD-UPZ-148' AS parent_code, 'union' AS area_type, 'Biaghat' AS name, 'BD-UNION-1332' AS code
  UNION ALL
    SELECT 'BD-UPZ-148' AS parent_code, 'union' AS area_type, 'Khubjipur' AS name, 'BD-UNION-1333' AS code
  UNION ALL
    SELECT 'BD-UPZ-148' AS parent_code, 'union' AS area_type, 'Dharabarisha' AS name, 'BD-UNION-1334' AS code
  UNION ALL
    SELECT 'BD-UPZ-148' AS parent_code, 'union' AS area_type, 'Moshindha' AS name, 'BD-UNION-1335' AS code
  UNION ALL
    SELECT 'BD-UPZ-148' AS parent_code, 'union' AS area_type, 'Chapila' AS name, 'BD-UNION-1336' AS code
  UNION ALL
    SELECT 'BD-UPZ-150' AS parent_code, 'union' AS area_type, 'Rukindipur' AS name, 'BD-UNION-1337' AS code
  UNION ALL
    SELECT 'BD-UPZ-150' AS parent_code, 'union' AS area_type, 'Sonamukhi' AS name, 'BD-UNION-1338' AS code
  UNION ALL
    SELECT 'BD-UPZ-150' AS parent_code, 'union' AS area_type, 'Tilakpur' AS name, 'BD-UNION-1339' AS code
  UNION ALL
    SELECT 'BD-UPZ-150' AS parent_code, 'union' AS area_type, 'Raikali' AS name, 'BD-UNION-1340' AS code
  UNION ALL
    SELECT 'BD-UPZ-150' AS parent_code, 'union' AS area_type, 'Gopinathpur' AS name, 'BD-UNION-1341' AS code
  UNION ALL
    SELECT 'BD-UPZ-151' AS parent_code, 'union' AS area_type, 'Matrai' AS name, 'BD-UNION-1342' AS code
  UNION ALL
    SELECT 'BD-UPZ-151' AS parent_code, 'union' AS area_type, 'Ahammedabad' AS name, 'BD-UNION-1343' AS code
  UNION ALL
    SELECT 'BD-UPZ-151' AS parent_code, 'union' AS area_type, 'Punot' AS name, 'BD-UNION-1344' AS code
  UNION ALL
    SELECT 'BD-UPZ-151' AS parent_code, 'union' AS area_type, 'Zindarpur' AS name, 'BD-UNION-1345' AS code
  UNION ALL
    SELECT 'BD-UPZ-151' AS parent_code, 'union' AS area_type, 'Udaipur' AS name, 'BD-UNION-1346' AS code
  UNION ALL
    SELECT 'BD-UPZ-152' AS parent_code, 'union' AS area_type, 'Alampur' AS name, 'BD-UNION-1347' AS code
  UNION ALL
    SELECT 'BD-UPZ-152' AS parent_code, 'union' AS area_type, 'Borail' AS name, 'BD-UNION-1348' AS code
  UNION ALL
    SELECT 'BD-UPZ-152' AS parent_code, 'union' AS area_type, 'Tulshiganga' AS name, 'BD-UNION-1349' AS code
  UNION ALL
    SELECT 'BD-UPZ-152' AS parent_code, 'union' AS area_type, 'Mamudpur' AS name, 'BD-UNION-1350' AS code
  UNION ALL
    SELECT 'BD-UPZ-152' AS parent_code, 'union' AS area_type, 'Boratara' AS name, 'BD-UNION-1351' AS code
  UNION ALL
    SELECT 'BD-UPZ-153' AS parent_code, 'union' AS area_type, 'Bagjana' AS name, 'BD-UNION-1352' AS code
  UNION ALL
    SELECT 'BD-UPZ-153' AS parent_code, 'union' AS area_type, 'Dharanji' AS name, 'BD-UNION-1353' AS code
  UNION ALL
    SELECT 'BD-UPZ-153' AS parent_code, 'union' AS area_type, 'Aymarasulpur' AS name, 'BD-UNION-1354' AS code
  UNION ALL
    SELECT 'BD-UPZ-153' AS parent_code, 'union' AS area_type, 'Balighata' AS name, 'BD-UNION-1355' AS code
  UNION ALL
    SELECT 'BD-UPZ-153' AS parent_code, 'union' AS area_type, 'Atapur' AS name, 'BD-UNION-1356' AS code
  UNION ALL
    SELECT 'BD-UPZ-153' AS parent_code, 'union' AS area_type, 'Mohammadpur' AS name, 'BD-UNION-1357' AS code
  UNION ALL
    SELECT 'BD-UPZ-153' AS parent_code, 'union' AS area_type, 'Aolai' AS name, 'BD-UNION-1358' AS code
  UNION ALL
    SELECT 'BD-UPZ-153' AS parent_code, 'union' AS area_type, 'Kusumba' AS name, 'BD-UNION-1359' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Amdai' AS name, 'BD-UNION-1360' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Bamb' AS name, 'BD-UNION-1361' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Dogachi' AS name, 'BD-UNION-1362' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Puranapail' AS name, 'BD-UNION-1363' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Jamalpur' AS name, 'BD-UNION-1364' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Chakborkat' AS name, 'BD-UNION-1365' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Mohammadabad' AS name, 'BD-UNION-1366' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Dhalahar' AS name, 'BD-UNION-1367' AS code
  UNION ALL
    SELECT 'BD-UPZ-154' AS parent_code, 'union' AS area_type, 'Bhadsha' AS name, 'BD-UNION-1368' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Alatuli' AS name, 'BD-UNION-1369' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Baroghoria' AS name, 'BD-UNION-1370' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Moharajpur' AS name, 'BD-UNION-1371' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Ranihati' AS name, 'BD-UNION-1372' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Baliadanga' AS name, 'BD-UNION-1373' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Gobratola' AS name, 'BD-UNION-1374' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Jhilim' AS name, 'BD-UNION-1375' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Char Anupnagar' AS name, 'BD-UNION-1376' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Debinagar' AS name, 'BD-UNION-1377' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Shahjahanpur' AS name, 'BD-UNION-1378' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Islampur' AS name, 'BD-UNION-1379' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Charbagdanga' AS name, 'BD-UNION-1380' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Narayanpur' AS name, 'BD-UNION-1381' AS code
  UNION ALL
    SELECT 'BD-UPZ-155' AS parent_code, 'union' AS area_type, 'Sundarpur' AS name, 'BD-UNION-1382' AS code
  UNION ALL
    SELECT 'BD-UPZ-156' AS parent_code, 'union' AS area_type, 'Radhanagar' AS name, 'BD-UNION-1383' AS code
  UNION ALL
    SELECT 'BD-UPZ-156' AS parent_code, 'union' AS area_type, 'Rahanpur' AS name, 'BD-UNION-1384' AS code
  UNION ALL
    SELECT 'BD-UPZ-156' AS parent_code, 'union' AS area_type, 'Boalia' AS name, 'BD-UNION-1385' AS code
  UNION ALL
    SELECT 'BD-UPZ-156' AS parent_code, 'union' AS area_type, 'Bangabari' AS name, 'BD-UNION-1386' AS code
  UNION ALL
    SELECT 'BD-UPZ-156' AS parent_code, 'union' AS area_type, 'Parbotipur' AS name, 'BD-UNION-1387' AS code
  UNION ALL
    SELECT 'BD-UPZ-156' AS parent_code, 'union' AS area_type, 'Chowdala' AS name, 'BD-UNION-1388' AS code
  UNION ALL
    SELECT 'BD-UPZ-156' AS parent_code, 'union' AS area_type, 'Gomostapur' AS name, 'BD-UNION-1389' AS code
  UNION ALL
    SELECT 'BD-UPZ-156' AS parent_code, 'union' AS area_type, 'Alinagar' AS name, 'BD-UNION-1390' AS code
  UNION ALL
    SELECT 'BD-UPZ-157' AS parent_code, 'union' AS area_type, 'Fhotepur' AS name, 'BD-UNION-1391' AS code
  UNION ALL
    SELECT 'BD-UPZ-157' AS parent_code, 'union' AS area_type, 'Kosba' AS name, 'BD-UNION-1392' AS code
  UNION ALL
    SELECT 'BD-UPZ-157' AS parent_code, 'union' AS area_type, 'Nezampur' AS name, 'BD-UNION-1393' AS code
  UNION ALL
    SELECT 'BD-UPZ-157' AS parent_code, 'union' AS area_type, 'Nachol' AS name, 'BD-UNION-1394' AS code
  UNION ALL
    SELECT 'BD-UPZ-158' AS parent_code, 'union' AS area_type, 'Bholahat' AS name, 'BD-UNION-1395' AS code
  UNION ALL
    SELECT 'BD-UPZ-158' AS parent_code, 'union' AS area_type, 'Jambaria' AS name, 'BD-UNION-1396' AS code
  UNION ALL
    SELECT 'BD-UPZ-158' AS parent_code, 'union' AS area_type, 'Gohalbari' AS name, 'BD-UNION-1397' AS code
  UNION ALL
    SELECT 'BD-UPZ-158' AS parent_code, 'union' AS area_type, 'Daldoli' AS name, 'BD-UNION-1398' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Binodpur' AS name, 'BD-UNION-1399' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Chakkirti' AS name, 'BD-UNION-1400' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Daipukuria' AS name, 'BD-UNION-1401' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Dhainagar' AS name, 'BD-UNION-1402' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Durlovpur' AS name, 'BD-UNION-1403' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Ghorapakhia' AS name, 'BD-UNION-1404' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Mobarakpur' AS name, 'BD-UNION-1405' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Monakasha' AS name, 'BD-UNION-1406' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Noyalavanga' AS name, 'BD-UNION-1407' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Panka' AS name, 'BD-UNION-1408' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Chatrajitpur' AS name, 'BD-UNION-1409' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Shahabajpur' AS name, 'BD-UNION-1410' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Shyampur' AS name, 'BD-UNION-1411' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Kansat' AS name, 'BD-UNION-1412' AS code
  UNION ALL
    SELECT 'BD-UPZ-159' AS parent_code, 'union' AS area_type, 'Ujirpur' AS name, 'BD-UNION-1413' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, '1nomohadevpur' AS name, 'BD-UNION-1414' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Hatur' AS name, 'BD-UNION-1415' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Khajur' AS name, 'BD-UNION-1416' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Chandas' AS name, 'BD-UNION-1417' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Enayetpur' AS name, 'BD-UNION-1418' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Sofapur' AS name, 'BD-UNION-1419' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Uttargram' AS name, 'BD-UNION-1420' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Cheragpur' AS name, 'BD-UNION-1421' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Vimpur' AS name, 'BD-UNION-1422' AS code
  UNION ALL
    SELECT 'BD-UPZ-160' AS parent_code, 'union' AS area_type, 'Roygon' AS name, 'BD-UNION-1423' AS code
  UNION ALL
    SELECT 'BD-UPZ-161' AS parent_code, 'union' AS area_type, 'Badalgachi' AS name, 'BD-UNION-1424' AS code
  UNION ALL
    SELECT 'BD-UPZ-161' AS parent_code, 'union' AS area_type, 'Mothurapur' AS name, 'BD-UNION-1425' AS code
  UNION ALL
    SELECT 'BD-UPZ-161' AS parent_code, 'union' AS area_type, 'Paharpur' AS name, 'BD-UNION-1426' AS code
  UNION ALL
    SELECT 'BD-UPZ-161' AS parent_code, 'union' AS area_type, 'Mithapur' AS name, 'BD-UNION-1427' AS code
  UNION ALL
    SELECT 'BD-UPZ-161' AS parent_code, 'union' AS area_type, 'Kola' AS name, 'BD-UNION-1428' AS code
  UNION ALL
    SELECT 'BD-UPZ-161' AS parent_code, 'union' AS area_type, 'Bilashbari' AS name, 'BD-UNION-1429' AS code
  UNION ALL
    SELECT 'BD-UPZ-161' AS parent_code, 'union' AS area_type, 'Adhaipur' AS name, 'BD-UNION-1430' AS code
  UNION ALL
    SELECT 'BD-UPZ-161' AS parent_code, 'union' AS area_type, 'Balubhara' AS name, 'BD-UNION-1431' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Patnitala' AS name, 'BD-UNION-1432' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Nirmail' AS name, 'BD-UNION-1433' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Dibar' AS name, 'BD-UNION-1434' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Akbarpur' AS name, 'BD-UNION-1435' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Matindar' AS name, 'BD-UNION-1436' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Krishnapur' AS name, 'BD-UNION-1437' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Patichrara' AS name, 'BD-UNION-1438' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Nazipur' AS name, 'BD-UNION-1439' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Ghasnagar' AS name, 'BD-UNION-1440' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Amair' AS name, 'BD-UNION-1441' AS code
  UNION ALL
    SELECT 'BD-UPZ-162' AS parent_code, 'union' AS area_type, 'Shihara' AS name, 'BD-UNION-1442' AS code
  UNION ALL
    SELECT 'BD-UPZ-163' AS parent_code, 'union' AS area_type, 'Dhamoirhat' AS name, 'BD-UNION-1443' AS code
  UNION ALL
    SELECT 'BD-UPZ-163' AS parent_code, 'union' AS area_type, 'Alampur' AS name, 'BD-UNION-1444' AS code
  UNION ALL
    SELECT 'BD-UPZ-163' AS parent_code, 'union' AS area_type, 'Umar' AS name, 'BD-UNION-1445' AS code
  UNION ALL
    SELECT 'BD-UPZ-163' AS parent_code, 'union' AS area_type, 'Aranagar' AS name, 'BD-UNION-1446' AS code
  UNION ALL
    SELECT 'BD-UPZ-163' AS parent_code, 'union' AS area_type, 'Jahanpur' AS name, 'BD-UNION-1447' AS code
  UNION ALL
    SELECT 'BD-UPZ-163' AS parent_code, 'union' AS area_type, 'Isabpur' AS name, 'BD-UNION-1448' AS code
  UNION ALL
    SELECT 'BD-UPZ-163' AS parent_code, 'union' AS area_type, 'Khelna' AS name, 'BD-UNION-1449' AS code
  UNION ALL
    SELECT 'BD-UPZ-163' AS parent_code, 'union' AS area_type, 'Agradigun' AS name, 'BD-UNION-1450' AS code
  UNION ALL
    SELECT 'BD-UPZ-164' AS parent_code, 'union' AS area_type, 'Hajinagar' AS name, 'BD-UNION-1451' AS code
  UNION ALL
    SELECT 'BD-UPZ-164' AS parent_code, 'union' AS area_type, 'Chandannagar' AS name, 'BD-UNION-1452' AS code
  UNION ALL
    SELECT 'BD-UPZ-164' AS parent_code, 'union' AS area_type, 'Bhabicha' AS name, 'BD-UNION-1453' AS code
  UNION ALL
    SELECT 'BD-UPZ-164' AS parent_code, 'union' AS area_type, 'Niamatpur' AS name, 'BD-UNION-1454' AS code
  UNION ALL
    SELECT 'BD-UPZ-164' AS parent_code, 'union' AS area_type, 'Rasulpur' AS name, 'BD-UNION-1455' AS code
  UNION ALL
    SELECT 'BD-UPZ-164' AS parent_code, 'union' AS area_type, 'Paroil' AS name, 'BD-UNION-1456' AS code
  UNION ALL
    SELECT 'BD-UPZ-164' AS parent_code, 'union' AS area_type, 'Sremantapur' AS name, 'BD-UNION-1457' AS code
  UNION ALL
    SELECT 'BD-UPZ-164' AS parent_code, 'union' AS area_type, 'Bahadurpur' AS name, 'BD-UNION-1458' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Varsho' AS name, 'BD-UNION-1459' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Valain' AS name, 'BD-UNION-1460' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Paranpur' AS name, 'BD-UNION-1461' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Manda' AS name, 'BD-UNION-1462' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Goneshpur' AS name, 'BD-UNION-1463' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Moinom' AS name, 'BD-UNION-1464' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Proshadpur' AS name, 'BD-UNION-1465' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Kosomba' AS name, 'BD-UNION-1466' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Tetulia' AS name, 'BD-UNION-1467' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Nurullabad' AS name, 'BD-UNION-1468' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Kalikapur' AS name, 'BD-UNION-1469' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Kashopara' AS name, 'BD-UNION-1470' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Koshob' AS name, 'BD-UNION-1471' AS code
  UNION ALL
    SELECT 'BD-UPZ-165' AS parent_code, 'union' AS area_type, 'Bisnopur' AS name, 'BD-UNION-1472' AS code
  UNION ALL
    SELECT 'BD-UPZ-166' AS parent_code, 'union' AS area_type, 'Shahagola' AS name, 'BD-UNION-1473' AS code
  UNION ALL
    SELECT 'BD-UPZ-166' AS parent_code, 'union' AS area_type, 'Bhonpara' AS name, 'BD-UNION-1474' AS code
  UNION ALL
    SELECT 'BD-UPZ-166' AS parent_code, 'union' AS area_type, 'Ahsanganj' AS name, 'BD-UNION-1475' AS code
  UNION ALL
    SELECT 'BD-UPZ-166' AS parent_code, 'union' AS area_type, 'Panchupur' AS name, 'BD-UNION-1476' AS code
  UNION ALL
    SELECT 'BD-UPZ-166' AS parent_code, 'union' AS area_type, 'Bisha' AS name, 'BD-UNION-1477' AS code
  UNION ALL
    SELECT 'BD-UPZ-166' AS parent_code, 'union' AS area_type, 'Maniary' AS name, 'BD-UNION-1478' AS code
  UNION ALL
    SELECT 'BD-UPZ-166' AS parent_code, 'union' AS area_type, 'Kalikapur' AS name, 'BD-UNION-1479' AS code
  UNION ALL
    SELECT 'BD-UPZ-166' AS parent_code, 'union' AS area_type, 'Hatkalupara' AS name, 'BD-UNION-1480' AS code
  UNION ALL
    SELECT 'BD-UPZ-167' AS parent_code, 'union' AS area_type, 'Khatteshawr' AS name, 'BD-UNION-1481' AS code
  UNION ALL
    SELECT 'BD-UPZ-167' AS parent_code, 'union' AS area_type, 'Kashimpur' AS name, 'BD-UNION-1482' AS code
  UNION ALL
    SELECT 'BD-UPZ-167' AS parent_code, 'union' AS area_type, 'Gona' AS name, 'BD-UNION-1483' AS code
  UNION ALL
    SELECT 'BD-UPZ-167' AS parent_code, 'union' AS area_type, 'Paroil' AS name, 'BD-UNION-1484' AS code
  UNION ALL
    SELECT 'BD-UPZ-167' AS parent_code, 'union' AS area_type, 'Borgoca' AS name, 'BD-UNION-1485' AS code
  UNION ALL
    SELECT 'BD-UPZ-167' AS parent_code, 'union' AS area_type, 'Kaligram' AS name, 'BD-UNION-1486' AS code
  UNION ALL
    SELECT 'BD-UPZ-167' AS parent_code, 'union' AS area_type, 'Ekdala' AS name, 'BD-UNION-1487' AS code
  UNION ALL
    SELECT 'BD-UPZ-167' AS parent_code, 'union' AS area_type, 'Mirat' AS name, 'BD-UNION-1488' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Barshail' AS name, 'BD-UNION-1489' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Kritipur' AS name, 'BD-UNION-1490' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Baktiarpur' AS name, 'BD-UNION-1491' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Tilakpur' AS name, 'BD-UNION-1492' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Hapaniya' AS name, 'BD-UNION-1493' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Dubalhati' AS name, 'BD-UNION-1494' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Boalia' AS name, 'BD-UNION-1495' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Hashaigari' AS name, 'BD-UNION-1496' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Chandipur' AS name, 'BD-UNION-1497' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Bolihar' AS name, 'BD-UNION-1498' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Shekerpur' AS name, 'BD-UNION-1499' AS code
  UNION ALL
    SELECT 'BD-UPZ-168' AS parent_code, 'union' AS area_type, 'Shailgachhi' AS name, 'BD-UNION-1500' AS code
  UNION ALL
    SELECT 'BD-UPZ-169' AS parent_code, 'union' AS area_type, 'Nitpur' AS name, 'BD-UNION-1501' AS code
  UNION ALL
    SELECT 'BD-UPZ-169' AS parent_code, 'union' AS area_type, 'Tetulia' AS name, 'BD-UNION-1502' AS code
  UNION ALL
    SELECT 'BD-UPZ-169' AS parent_code, 'union' AS area_type, 'Chhaor' AS name, 'BD-UNION-1503' AS code
  UNION ALL
    SELECT 'BD-UPZ-169' AS parent_code, 'union' AS area_type, 'Ganguria' AS name, 'BD-UNION-1504' AS code
  UNION ALL
    SELECT 'BD-UPZ-169' AS parent_code, 'union' AS area_type, 'Ghatnagar' AS name, 'BD-UNION-1505' AS code
  UNION ALL
    SELECT 'BD-UPZ-169' AS parent_code, 'union' AS area_type, 'Moshidpur' AS name, 'BD-UNION-1506' AS code
  UNION ALL
    SELECT 'BD-UPZ-170' AS parent_code, 'union' AS area_type, 'Sapahar' AS name, 'BD-UNION-1507' AS code
  UNION ALL
    SELECT 'BD-UPZ-170' AS parent_code, 'union' AS area_type, 'Tilna' AS name, 'BD-UNION-1508' AS code
  UNION ALL
    SELECT 'BD-UPZ-170' AS parent_code, 'union' AS area_type, 'Aihai' AS name, 'BD-UNION-1509' AS code
  UNION ALL
    SELECT 'BD-UPZ-170' AS parent_code, 'union' AS area_type, 'Shironti' AS name, 'BD-UNION-1510' AS code
  UNION ALL
    SELECT 'BD-UPZ-170' AS parent_code, 'union' AS area_type, 'Goala' AS name, 'BD-UNION-1511' AS code
  UNION ALL
    SELECT 'BD-UPZ-170' AS parent_code, 'union' AS area_type, 'Patari' AS name, 'BD-UNION-1512' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Nehalpur' AS name, 'BD-UNION-1513' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Hariharnagar' AS name, 'BD-UNION-1514' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Haridaskati' AS name, 'BD-UNION-1515' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Shyamkur' AS name, 'BD-UNION-1516' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Rohita' AS name, 'BD-UNION-1517' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Maswimnagar' AS name, 'BD-UNION-1518' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Manoharpur' AS name, 'BD-UNION-1519' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Manirampur' AS name, 'BD-UNION-1520' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Bhojgati' AS name, 'BD-UNION-1521' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Durbadanga' AS name, 'BD-UNION-1522' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Dhakuria' AS name, 'BD-UNION-1523' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Jhanpa' AS name, 'BD-UNION-1524' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Chaluahati' AS name, 'BD-UNION-1525' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Khedapara' AS name, 'BD-UNION-1526' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Khanpur' AS name, 'BD-UNION-1527' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Kultia' AS name, 'BD-UNION-1528' AS code
  UNION ALL
    SELECT 'BD-UPZ-171' AS parent_code, 'union' AS area_type, 'Kashimnagar' AS name, 'BD-UNION-1529' AS code
  UNION ALL
    SELECT 'BD-UPZ-172' AS parent_code, 'union' AS area_type, 'Baghutia' AS name, 'BD-UNION-1530' AS code
  UNION ALL
    SELECT 'BD-UPZ-172' AS parent_code, 'union' AS area_type, 'Chalishia' AS name, 'BD-UNION-1531' AS code
  UNION ALL
    SELECT 'BD-UPZ-172' AS parent_code, 'union' AS area_type, 'Sundoli' AS name, 'BD-UNION-1532' AS code
  UNION ALL
    SELECT 'BD-UPZ-172' AS parent_code, 'union' AS area_type, 'Siddhipasha' AS name, 'BD-UNION-1533' AS code
  UNION ALL
    SELECT 'BD-UPZ-172' AS parent_code, 'union' AS area_type, 'Sreedharpur' AS name, 'BD-UNION-1534' AS code
  UNION ALL
    SELECT 'BD-UPZ-172' AS parent_code, 'union' AS area_type, 'Subharara' AS name, 'BD-UNION-1535' AS code
  UNION ALL
    SELECT 'BD-UPZ-172' AS parent_code, 'union' AS area_type, 'Prambag' AS name, 'BD-UNION-1536' AS code
  UNION ALL
    SELECT 'BD-UPZ-172' AS parent_code, 'union' AS area_type, 'Payra' AS name, 'BD-UNION-1537' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Jaharpur' AS name, 'BD-UNION-1538' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Jamdia' AS name, 'BD-UNION-1539' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Darajhat' AS name, 'BD-UNION-1540' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Dhalgram' AS name, 'BD-UNION-1541' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Narikelbaria' AS name, 'BD-UNION-1542' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Bandabilla' AS name, 'BD-UNION-1543' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Basuari' AS name, 'BD-UNION-1544' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Roypur' AS name, 'BD-UNION-1545' AS code
  UNION ALL
    SELECT 'BD-UPZ-173' AS parent_code, 'union' AS area_type, 'Dohakula' AS name, 'BD-UNION-1546' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Chougachha' AS name, 'BD-UNION-1547' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Jagadishpur' AS name, 'BD-UNION-1548' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Dhuliani' AS name, 'BD-UNION-1549' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Narayanpur' AS name, 'BD-UNION-1550' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Patibila' AS name, 'BD-UNION-1551' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Pashapole' AS name, 'BD-UNION-1552' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Fulsara' AS name, 'BD-UNION-1553' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Singhajhuli' AS name, 'BD-UNION-1554' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Sukpukhuria' AS name, 'BD-UNION-1555' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Swarupdaha' AS name, 'BD-UNION-1556' AS code
  UNION ALL
    SELECT 'BD-UPZ-174' AS parent_code, 'union' AS area_type, 'Hakimpur' AS name, 'BD-UNION-1557' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Gangananda' AS name, 'BD-UNION-1558' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Gadkhali' AS name, 'BD-UNION-1559' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Jhikargachha' AS name, 'BD-UNION-1560' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Nabharan' AS name, 'BD-UNION-1561' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Nibaskhola' AS name, 'BD-UNION-1562' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Panisara' AS name, 'BD-UNION-1563' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Bankra' AS name, 'BD-UNION-1564' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Shankarpur' AS name, 'BD-UNION-1565' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Shimulia' AS name, 'BD-UNION-1566' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Hajirbagh' AS name, 'BD-UNION-1567' AS code
  UNION ALL
    SELECT 'BD-UPZ-175' AS parent_code, 'union' AS area_type, 'Magura' AS name, 'BD-UNION-1568' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Sufalakati' AS name, 'BD-UNION-1569' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Sagardari' AS name, 'BD-UNION-1570' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Majidpur' AS name, 'BD-UNION-1571' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Mongolkot' AS name, 'BD-UNION-1572' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Bidyanandakati' AS name, 'BD-UNION-1573' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Panjia' AS name, 'BD-UNION-1574' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Trimohini' AS name, 'BD-UNION-1575' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Gaurighona' AS name, 'BD-UNION-1576' AS code
  UNION ALL
    SELECT 'BD-UPZ-176' AS parent_code, 'union' AS area_type, 'Keshabpur' AS name, 'BD-UNION-1577' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Lebutala' AS name, 'BD-UNION-1578' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Ichhali' AS name, 'BD-UNION-1579' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Arabpur' AS name, 'BD-UNION-1580' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Upasahar' AS name, 'BD-UNION-1581' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Kachua' AS name, 'BD-UNION-1582' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Kashimpur' AS name, 'BD-UNION-1583' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Chanchra' AS name, 'BD-UNION-1584' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Churamankati' AS name, 'BD-UNION-1585' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Narendrapur' AS name, 'BD-UNION-1586' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Noapara' AS name, 'BD-UNION-1587' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Fathehpur' AS name, 'BD-UNION-1588' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Basundia' AS name, 'BD-UNION-1589' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Ramnagar' AS name, 'BD-UNION-1590' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Haibatpur' AS name, 'BD-UNION-1591' AS code
  UNION ALL
    SELECT 'BD-UPZ-177' AS parent_code, 'union' AS area_type, 'Dearamodel' AS name, 'BD-UNION-1592' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Ulshi' AS name, 'BD-UNION-1593' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Sharsha' AS name, 'BD-UNION-1594' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Lakshmanpur' AS name, 'BD-UNION-1595' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Benapole' AS name, 'BD-UNION-1596' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Bahadurpur' AS name, 'BD-UNION-1597' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Bagachra' AS name, 'BD-UNION-1598' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Putkhali' AS name, 'BD-UNION-1599' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Nizampur' AS name, 'BD-UNION-1600' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;

INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
SELECT p.id, v.area_type, v.name, v.code
FROM (
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Dihi' AS name, 'BD-UNION-1601' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Goga' AS name, 'BD-UNION-1602' AS code
  UNION ALL
    SELECT 'BD-UPZ-178' AS parent_code, 'union' AS area_type, 'Kayba' AS name, 'BD-UNION-1603' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Anulia' AS name, 'BD-UNION-1604' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Assasuni' AS name, 'BD-UNION-1605' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Kadakati' AS name, 'BD-UNION-1606' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Kulla' AS name, 'BD-UNION-1607' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Khajra' AS name, 'BD-UNION-1608' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Durgapur' AS name, 'BD-UNION-1609' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Pratapnagar' AS name, 'BD-UNION-1610' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Budhhata' AS name, 'BD-UNION-1611' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Baradal' AS name, 'BD-UNION-1612' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Sreeula' AS name, 'BD-UNION-1613' AS code
  UNION ALL
    SELECT 'BD-UPZ-179' AS parent_code, 'union' AS area_type, 'Sobhnali' AS name, 'BD-UNION-1614' AS code
  UNION ALL
    SELECT 'BD-UPZ-180' AS parent_code, 'union' AS area_type, 'Kulia' AS name, 'BD-UNION-1615' AS code
  UNION ALL
    SELECT 'BD-UPZ-180' AS parent_code, 'union' AS area_type, 'Debhata' AS name, 'BD-UNION-1616' AS code
  UNION ALL
    SELECT 'BD-UPZ-180' AS parent_code, 'union' AS area_type, 'Noapara' AS name, 'BD-UNION-1617' AS code
  UNION ALL
    SELECT 'BD-UPZ-180' AS parent_code, 'union' AS area_type, 'Parulia' AS name, 'BD-UNION-1618' AS code
  UNION ALL
    SELECT 'BD-UPZ-180' AS parent_code, 'union' AS area_type, 'Sakhipur' AS name, 'BD-UNION-1619' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Kushadanga' AS name, 'BD-UNION-1620' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Keralkata' AS name, 'BD-UNION-1621' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Keragachhi' AS name, 'BD-UNION-1622' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Kaila' AS name, 'BD-UNION-1623' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Jallabad' AS name, 'BD-UNION-1624' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Jogikhali' AS name, 'BD-UNION-1625' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Langaljhara' AS name, 'BD-UNION-1626' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Sonabaria' AS name, 'BD-UNION-1627' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Helatala' AS name, 'BD-UNION-1628' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Chandanpur' AS name, 'BD-UNION-1629' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Deara' AS name, 'BD-UNION-1630' AS code
  UNION ALL
    SELECT 'BD-UPZ-181' AS parent_code, 'union' AS area_type, 'Joynagar' AS name, 'BD-UNION-1631' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Shibpur' AS name, 'BD-UNION-1632' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Labsa' AS name, 'BD-UNION-1633' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Bhomra' AS name, 'BD-UNION-1634' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Brahmarajpur' AS name, 'BD-UNION-1635' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Balli' AS name, 'BD-UNION-1636' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Banshdaha' AS name, 'BD-UNION-1637' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Baikari' AS name, 'BD-UNION-1638' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Fingri' AS name, 'BD-UNION-1639' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Dhulihar' AS name, 'BD-UNION-1640' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Jhaudanga' AS name, 'BD-UNION-1641' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Ghona' AS name, 'BD-UNION-1642' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Kuskhali' AS name, 'BD-UNION-1643' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Alipur' AS name, 'BD-UNION-1644' AS code
  UNION ALL
    SELECT 'BD-UPZ-182' AS parent_code, 'union' AS area_type, 'Agardari' AS name, 'BD-UNION-1645' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Atulia' AS name, 'BD-UNION-1646' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Ishwaripur' AS name, 'BD-UNION-1647' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Kaikhali' AS name, 'BD-UNION-1648' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Kashimari' AS name, 'BD-UNION-1649' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Nurnagar' AS name, 'BD-UNION-1650' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Padmapukur' AS name, 'BD-UNION-1651' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Burigoalini' AS name, 'BD-UNION-1652' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Bhurulia' AS name, 'BD-UNION-1653' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Munshiganj' AS name, 'BD-UNION-1654' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Ramjannagar' AS name, 'BD-UNION-1655' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Shyamnagar' AS name, 'BD-UNION-1656' AS code
  UNION ALL
    SELECT 'BD-UPZ-183' AS parent_code, 'union' AS area_type, 'Gabura' AS name, 'BD-UNION-1657' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Sarulia' AS name, 'BD-UNION-1658' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Magura' AS name, 'BD-UNION-1659' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Nagarghata' AS name, 'BD-UNION-1660' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Dhandia' AS name, 'BD-UNION-1661' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Tentulia' AS name, 'BD-UNION-1662' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Tala' AS name, 'BD-UNION-1663' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Jalalpur' AS name, 'BD-UNION-1664' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Khesra' AS name, 'BD-UNION-1665' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Khalishkhali' AS name, 'BD-UNION-1666' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Khalilnagar' AS name, 'BD-UNION-1667' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Kumira' AS name, 'BD-UNION-1668' AS code
  UNION ALL
    SELECT 'BD-UPZ-184' AS parent_code, 'union' AS area_type, 'Islamkati' AS name, 'BD-UNION-1669' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Kushlia' AS name, 'BD-UNION-1670' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Champaphul' AS name, 'BD-UNION-1671' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Tarali' AS name, 'BD-UNION-1672' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Dakshin Sreepur' AS name, 'BD-UNION-1673' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Dhalbaria' AS name, 'BD-UNION-1674' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Nalta' AS name, 'BD-UNION-1675' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Bishnupur' AS name, 'BD-UNION-1676' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Bharasimla' AS name, 'BD-UNION-1677' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Mathureshpur' AS name, 'BD-UNION-1678' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Ratanpur' AS name, 'BD-UNION-1679' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Mautala' AS name, 'BD-UNION-1680' AS code
  UNION ALL
    SELECT 'BD-UPZ-185' AS parent_code, 'union' AS area_type, 'Krishnanagar' AS name, 'BD-UNION-1681' AS code
  UNION ALL
    SELECT 'BD-UPZ-186' AS parent_code, 'union' AS area_type, 'Dariapur' AS name, 'BD-UNION-1682' AS code
  UNION ALL
    SELECT 'BD-UPZ-186' AS parent_code, 'union' AS area_type, 'Monakhali' AS name, 'BD-UNION-1683' AS code
  UNION ALL
    SELECT 'BD-UPZ-186' AS parent_code, 'union' AS area_type, 'Bagowan' AS name, 'BD-UNION-1684' AS code
  UNION ALL
    SELECT 'BD-UPZ-186' AS parent_code, 'union' AS area_type, 'Mohajanpur' AS name, 'BD-UNION-1685' AS code
  UNION ALL
    SELECT 'BD-UPZ-187' AS parent_code, 'union' AS area_type, 'Amjhupi' AS name, 'BD-UNION-1686' AS code
  UNION ALL
    SELECT 'BD-UPZ-187' AS parent_code, 'union' AS area_type, 'Pirojpur' AS name, 'BD-UNION-1687' AS code
  UNION ALL
    SELECT 'BD-UPZ-187' AS parent_code, 'union' AS area_type, 'Kutubpur' AS name, 'BD-UNION-1688' AS code
  UNION ALL
    SELECT 'BD-UPZ-187' AS parent_code, 'union' AS area_type, 'Amdah' AS name, 'BD-UNION-1689' AS code
  UNION ALL
    SELECT 'BD-UPZ-187' AS parent_code, 'union' AS area_type, 'Buripota' AS name, 'BD-UNION-1690' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Tentulbaria' AS name, 'BD-UNION-1691' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Kazipur' AS name, 'BD-UNION-1692' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Bamondi' AS name, 'BD-UNION-1693' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Motmura' AS name, 'BD-UNION-1694' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Sholotaka' AS name, 'BD-UNION-1695' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Shaharbati' AS name, 'BD-UNION-1696' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Dhankolla' AS name, 'BD-UNION-1697' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Raipur' AS name, 'BD-UNION-1698' AS code
  UNION ALL
    SELECT 'BD-UPZ-188' AS parent_code, 'union' AS area_type, 'Kathuli' AS name, 'BD-UNION-1699' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Sheikhati' AS name, 'BD-UNION-1700' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Tularampur' AS name, 'BD-UNION-1701' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Kalora' AS name, 'BD-UNION-1702' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Shahabad' AS name, 'BD-UNION-1703' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Bashgram' AS name, 'BD-UNION-1704' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Habokhali' AS name, 'BD-UNION-1705' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Maijpara' AS name, 'BD-UNION-1706' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Bisali' AS name, 'BD-UNION-1707' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Chandiborpur' AS name, 'BD-UNION-1708' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Bhadrabila' AS name, 'BD-UNION-1709' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Auria' AS name, 'BD-UNION-1710' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Singasholpur' AS name, 'BD-UNION-1711' AS code
  UNION ALL
    SELECT 'BD-UPZ-189' AS parent_code, 'union' AS area_type, 'Mulia' AS name, 'BD-UNION-1712' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Lohagora' AS name, 'BD-UNION-1713' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Kashipur' AS name, 'BD-UNION-1714' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Naldi' AS name, 'BD-UNION-1715' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Noagram' AS name, 'BD-UNION-1716' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Lahuria' AS name, 'BD-UNION-1717' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Mallikpur' AS name, 'BD-UNION-1718' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Salnagar' AS name, 'BD-UNION-1719' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Lakshmipasha' AS name, 'BD-UNION-1720' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Joypur' AS name, 'BD-UNION-1721' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Kotakol' AS name, 'BD-UNION-1722' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Digholia' AS name, 'BD-UNION-1723' AS code
  UNION ALL
    SELECT 'BD-UPZ-190' AS parent_code, 'union' AS area_type, 'Itna' AS name, 'BD-UNION-1724' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Jaynagor' AS name, 'BD-UNION-1725' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Pahordanga' AS name, 'BD-UNION-1726' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Babrahasla' AS name, 'BD-UNION-1727' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Salamabad' AS name, 'BD-UNION-1728' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Baioshona' AS name, 'BD-UNION-1729' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Chacuri' AS name, 'BD-UNION-1730' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Hamidpur' AS name, 'BD-UNION-1731' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Peroli' AS name, 'BD-UNION-1732' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Khashial' AS name, 'BD-UNION-1733' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Purulia' AS name, 'BD-UNION-1734' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Kalabaria' AS name, 'BD-UNION-1735' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Mauli' AS name, 'BD-UNION-1736' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Boronaleliasabad' AS name, 'BD-UNION-1737' AS code
  UNION ALL
    SELECT 'BD-UPZ-191' AS parent_code, 'union' AS area_type, 'Panchgram' AS name, 'BD-UNION-1738' AS code
  UNION ALL
    SELECT 'BD-UPZ-192' AS parent_code, 'union' AS area_type, 'Alukdia' AS name, 'BD-UNION-1739' AS code
  UNION ALL
    SELECT 'BD-UPZ-192' AS parent_code, 'union' AS area_type, 'Mominpur' AS name, 'BD-UNION-1740' AS code
  UNION ALL
    SELECT 'BD-UPZ-192' AS parent_code, 'union' AS area_type, 'Titudah' AS name, 'BD-UNION-1741' AS code
  UNION ALL
    SELECT 'BD-UPZ-192' AS parent_code, 'union' AS area_type, 'Shankarchandra' AS name, 'BD-UNION-1742' AS code
  UNION ALL
    SELECT 'BD-UPZ-192' AS parent_code, 'union' AS area_type, 'Begumpur' AS name, 'BD-UNION-1743' AS code
  UNION ALL
    SELECT 'BD-UPZ-192' AS parent_code, 'union' AS area_type, 'Kutubpur' AS name, 'BD-UNION-1744' AS code
  UNION ALL
    SELECT 'BD-UPZ-192' AS parent_code, 'union' AS area_type, 'Padmabila' AS name, 'BD-UNION-1745' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Bhangbaria' AS name, 'BD-UNION-1746' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Baradi' AS name, 'BD-UNION-1747' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Gangni' AS name, 'BD-UNION-1748' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Khadimpur' AS name, 'BD-UNION-1749' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Jehala' AS name, 'BD-UNION-1750' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Belgachi' AS name, 'BD-UNION-1751' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Dauki' AS name, 'BD-UNION-1752' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Jamjami' AS name, 'BD-UNION-1753' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Nagdah' AS name, 'BD-UNION-1754' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Kashkorara' AS name, 'BD-UNION-1755' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Chitla' AS name, 'BD-UNION-1756' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Kalidashpur' AS name, 'BD-UNION-1757' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Kumari' AS name, 'BD-UNION-1758' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Hardi' AS name, 'BD-UNION-1759' AS code
  UNION ALL
    SELECT 'BD-UPZ-193' AS parent_code, 'union' AS area_type, 'Ailhash' AS name, 'BD-UNION-1760' AS code
  UNION ALL
    SELECT 'BD-UPZ-194' AS parent_code, 'union' AS area_type, 'Damurhuda' AS name, 'BD-UNION-1761' AS code
  UNION ALL
    SELECT 'BD-UPZ-194' AS parent_code, 'union' AS area_type, 'Karpashdanga' AS name, 'BD-UNION-1762' AS code
  UNION ALL
    SELECT 'BD-UPZ-194' AS parent_code, 'union' AS area_type, 'Natipota' AS name, 'BD-UNION-1763' AS code
  UNION ALL
    SELECT 'BD-UPZ-194' AS parent_code, 'union' AS area_type, 'Hawli' AS name, 'BD-UNION-1764' AS code
  UNION ALL
    SELECT 'BD-UPZ-194' AS parent_code, 'union' AS area_type, 'Kurulgachhi' AS name, 'BD-UNION-1765' AS code
  UNION ALL
    SELECT 'BD-UPZ-194' AS parent_code, 'union' AS area_type, 'Perkrishnopur Madna' AS name, 'BD-UNION-1766' AS code
  UNION ALL
    SELECT 'BD-UPZ-194' AS parent_code, 'union' AS area_type, 'Juranpur' AS name, 'BD-UNION-1767' AS code
  UNION ALL
    SELECT 'BD-UPZ-195' AS parent_code, 'union' AS area_type, 'Uthali' AS name, 'BD-UNION-1768' AS code
  UNION ALL
    SELECT 'BD-UPZ-195' AS parent_code, 'union' AS area_type, 'Andulbaria' AS name, 'BD-UNION-1769' AS code
  UNION ALL
    SELECT 'BD-UPZ-195' AS parent_code, 'union' AS area_type, 'Banka' AS name, 'BD-UNION-1770' AS code
  UNION ALL
    SELECT 'BD-UPZ-195' AS parent_code, 'union' AS area_type, 'Shimanto' AS name, 'BD-UNION-1771' AS code
  UNION ALL
    SELECT 'BD-UPZ-195' AS parent_code, 'union' AS area_type, 'Raypur' AS name, 'BD-UNION-1772' AS code
  UNION ALL
    SELECT 'BD-UPZ-195' AS parent_code, 'union' AS area_type, 'Hasadah' AS name, 'BD-UNION-1773' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Hatash Haripur' AS name, 'BD-UNION-1774' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Barkhada' AS name, 'BD-UNION-1775' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Mazampur' AS name, 'BD-UNION-1776' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Bottail' AS name, 'BD-UNION-1777' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Alampur' AS name, 'BD-UNION-1778' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Ziaraakhi' AS name, 'BD-UNION-1779' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Ailchara' AS name, 'BD-UNION-1780' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Patikabari' AS name, 'BD-UNION-1781' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Jhaudia' AS name, 'BD-UNION-1782' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Ujangram' AS name, 'BD-UNION-1783' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Abdulpur' AS name, 'BD-UNION-1784' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Harinarayanpur' AS name, 'BD-UNION-1785' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Monohardia' AS name, 'BD-UNION-1786' AS code
  UNION ALL
    SELECT 'BD-UPZ-196' AS parent_code, 'union' AS area_type, 'Goswami Durgapur' AS name, 'BD-UNION-1787' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Kaya' AS name, 'BD-UNION-1788' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Jagonnathpur' AS name, 'BD-UNION-1789' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Sadki' AS name, 'BD-UNION-1790' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Shelaidah' AS name, 'BD-UNION-1791' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Nandolalpur' AS name, 'BD-UNION-1792' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Chapra' AS name, 'BD-UNION-1793' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Bagulat' AS name, 'BD-UNION-1794' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Jaduboyra' AS name, 'BD-UNION-1795' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Chadpur' AS name, 'BD-UNION-1796' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Panti' AS name, 'BD-UNION-1797' AS code
  UNION ALL
    SELECT 'BD-UPZ-197' AS parent_code, 'union' AS area_type, 'Charsadipur' AS name, 'BD-UNION-1798' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Khoksa' AS name, 'BD-UNION-1799' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Osmanpur' AS name, 'BD-UNION-1800' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Janipur' AS name, 'BD-UNION-1801' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Shimulia' AS name, 'BD-UNION-1802' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Joyntihazra' AS name, 'BD-UNION-1803' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Ambaria' AS name, 'BD-UNION-1804' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Bethbaria' AS name, 'BD-UNION-1805' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Shomospur' AS name, 'BD-UNION-1806' AS code
  UNION ALL
    SELECT 'BD-UPZ-198' AS parent_code, 'union' AS area_type, 'Gopgram' AS name, 'BD-UNION-1807' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Chithalia' AS name, 'BD-UNION-1808' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Bahalbaria' AS name, 'BD-UNION-1809' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Talbaria' AS name, 'BD-UNION-1810' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Baruipara' AS name, 'BD-UNION-1811' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Fulbaria' AS name, 'BD-UNION-1812' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Amla' AS name, 'BD-UNION-1813' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Sadarpur' AS name, 'BD-UNION-1814' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Chhatian' AS name, 'BD-UNION-1815' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Poradaha' AS name, 'BD-UNION-1816' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Kursha' AS name, 'BD-UNION-1817' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Ambaria' AS name, 'BD-UNION-1818' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Dhubail' AS name, 'BD-UNION-1819' AS code
  UNION ALL
    SELECT 'BD-UPZ-199' AS parent_code, 'union' AS area_type, 'Malihad' AS name, 'BD-UNION-1820' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Daulatpur' AS name, 'BD-UNION-1821' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Adabaria' AS name, 'BD-UNION-1822' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Hogolbaria' AS name, 'BD-UNION-1823' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Boalia' AS name, 'BD-UNION-1824' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Philipnagor' AS name, 'BD-UNION-1825' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Aria' AS name, 'BD-UNION-1826' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Khalishakundi' AS name, 'BD-UNION-1827' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Chilmary' AS name, 'BD-UNION-1828' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Mothurapur' AS name, 'BD-UNION-1829' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Pragpur' AS name, 'BD-UNION-1830' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Piarpur' AS name, 'BD-UNION-1831' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Moricha' AS name, 'BD-UNION-1832' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Refaitpur' AS name, 'BD-UNION-1833' AS code
  UNION ALL
    SELECT 'BD-UPZ-200' AS parent_code, 'union' AS area_type, 'Ramkrishnopur' AS name, 'BD-UNION-1834' AS code
  UNION ALL
    SELECT 'BD-UPZ-201' AS parent_code, 'union' AS area_type, 'Dharampur' AS name, 'BD-UNION-1835' AS code
  UNION ALL
    SELECT 'BD-UPZ-201' AS parent_code, 'union' AS area_type, 'Bahirchar' AS name, 'BD-UNION-1836' AS code
  UNION ALL
    SELECT 'BD-UPZ-201' AS parent_code, 'union' AS area_type, 'Mukarimpur' AS name, 'BD-UNION-1837' AS code
  UNION ALL
    SELECT 'BD-UPZ-201' AS parent_code, 'union' AS area_type, 'Juniadah' AS name, 'BD-UNION-1838' AS code
  UNION ALL
    SELECT 'BD-UPZ-201' AS parent_code, 'union' AS area_type, 'Chandgram' AS name, 'BD-UNION-1839' AS code
  UNION ALL
    SELECT 'BD-UPZ-201' AS parent_code, 'union' AS area_type, 'Bahadurpur' AS name, 'BD-UNION-1840' AS code
  UNION ALL
    SELECT 'BD-UPZ-202' AS parent_code, 'union' AS area_type, 'Dhaneshwargati' AS name, 'BD-UNION-1841' AS code
  UNION ALL
    SELECT 'BD-UPZ-202' AS parent_code, 'union' AS area_type, 'Talkhari' AS name, 'BD-UNION-1842' AS code
  UNION ALL
    SELECT 'BD-UPZ-202' AS parent_code, 'union' AS area_type, 'Arpara' AS name, 'BD-UNION-1843' AS code
  UNION ALL
    SELECT 'BD-UPZ-202' AS parent_code, 'union' AS area_type, 'Shatakhali' AS name, 'BD-UNION-1844' AS code
  UNION ALL
    SELECT 'BD-UPZ-202' AS parent_code, 'union' AS area_type, 'Shalikha' AS name, 'BD-UNION-1845' AS code
  UNION ALL
    SELECT 'BD-UPZ-202' AS parent_code, 'union' AS area_type, 'Bunagati' AS name, 'BD-UNION-1846' AS code
  UNION ALL
    SELECT 'BD-UPZ-202' AS parent_code, 'union' AS area_type, 'Gongarampur' AS name, 'BD-UNION-1847' AS code
  UNION ALL
    SELECT 'BD-UPZ-203' AS parent_code, 'union' AS area_type, 'Goyespur' AS name, 'BD-UNION-1848' AS code
  UNION ALL
    SELECT 'BD-UPZ-203' AS parent_code, 'union' AS area_type, 'Sreekol' AS name, 'BD-UNION-1849' AS code
  UNION ALL
    SELECT 'BD-UPZ-203' AS parent_code, 'union' AS area_type, 'Dariapur' AS name, 'BD-UNION-1850' AS code
  UNION ALL
    SELECT 'BD-UPZ-203' AS parent_code, 'union' AS area_type, 'Kadirpara' AS name, 'BD-UNION-1851' AS code
  UNION ALL
    SELECT 'BD-UPZ-203' AS parent_code, 'union' AS area_type, 'Shobdalpur' AS name, 'BD-UNION-1852' AS code
  UNION ALL
    SELECT 'BD-UPZ-203' AS parent_code, 'union' AS area_type, 'Sreepur' AS name, 'BD-UNION-1853' AS code
  UNION ALL
    SELECT 'BD-UPZ-203' AS parent_code, 'union' AS area_type, 'Nakol' AS name, 'BD-UNION-1854' AS code
  UNION ALL
    SELECT 'BD-UPZ-203' AS parent_code, 'union' AS area_type, 'Amalshar' AS name, 'BD-UNION-1855' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Hazipur' AS name, 'BD-UNION-1856' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Atharokhada' AS name, 'BD-UNION-1857' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Kosundi' AS name, 'BD-UNION-1858' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Bogia' AS name, 'BD-UNION-1859' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Hazrapur' AS name, 'BD-UNION-1860' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Raghobdair' AS name, 'BD-UNION-1861' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Jagdal' AS name, 'BD-UNION-1862' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Chawlia' AS name, 'BD-UNION-1863' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Satrijitpur' AS name, 'BD-UNION-1864' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Baroilpolita' AS name, 'BD-UNION-1865' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Kuchiamora' AS name, 'BD-UNION-1866' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Gopalgram' AS name, 'BD-UNION-1867' AS code
  UNION ALL
    SELECT 'BD-UPZ-204' AS parent_code, 'union' AS area_type, 'Moghi' AS name, 'BD-UNION-1868' AS code
  UNION ALL
    SELECT 'BD-UPZ-205' AS parent_code, 'union' AS area_type, 'Digha' AS name, 'BD-UNION-1869' AS code
  UNION ALL
    SELECT 'BD-UPZ-205' AS parent_code, 'union' AS area_type, 'Nohata' AS name, 'BD-UNION-1870' AS code
  UNION ALL
    SELECT 'BD-UPZ-205' AS parent_code, 'union' AS area_type, 'Palashbaria' AS name, 'BD-UNION-1871' AS code
  UNION ALL
    SELECT 'BD-UPZ-205' AS parent_code, 'union' AS area_type, 'Babukhali' AS name, 'BD-UNION-1872' AS code
  UNION ALL
    SELECT 'BD-UPZ-205' AS parent_code, 'union' AS area_type, 'Balidia' AS name, 'BD-UNION-1873' AS code
  UNION ALL
    SELECT 'BD-UPZ-205' AS parent_code, 'union' AS area_type, 'Binodpur' AS name, 'BD-UNION-1874' AS code
  UNION ALL
    SELECT 'BD-UPZ-205' AS parent_code, 'union' AS area_type, 'Mohammadpur' AS name, 'BD-UNION-1875' AS code
  UNION ALL
    SELECT 'BD-UPZ-205' AS parent_code, 'union' AS area_type, 'Rajapur' AS name, 'BD-UNION-1876' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Horidhali' AS name, 'BD-UNION-1877' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Goroikhali' AS name, 'BD-UNION-1878' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Kopilmuni' AS name, 'BD-UNION-1879' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Lota' AS name, 'BD-UNION-1880' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Deluti' AS name, 'BD-UNION-1881' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Loskor' AS name, 'BD-UNION-1882' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Godaipur' AS name, 'BD-UNION-1883' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Raruli' AS name, 'BD-UNION-1884' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Chandkhali' AS name, 'BD-UNION-1885' AS code
  UNION ALL
    SELECT 'BD-UPZ-206' AS parent_code, 'union' AS area_type, 'Soladana' AS name, 'BD-UNION-1886' AS code
  UNION ALL
    SELECT 'BD-UPZ-207' AS parent_code, 'union' AS area_type, 'Fultola' AS name, 'BD-UNION-1887' AS code
  UNION ALL
    SELECT 'BD-UPZ-207' AS parent_code, 'union' AS area_type, 'Damodar' AS name, 'BD-UNION-1888' AS code
  UNION ALL
    SELECT 'BD-UPZ-207' AS parent_code, 'union' AS area_type, 'Atra Gilatola' AS name, 'BD-UNION-1889' AS code
  UNION ALL
    SELECT 'BD-UPZ-207' AS parent_code, 'union' AS area_type, 'Jamira' AS name, 'BD-UNION-1890' AS code
  UNION ALL
    SELECT 'BD-UPZ-208' AS parent_code, 'union' AS area_type, 'Senhati' AS name, 'BD-UNION-1891' AS code
  UNION ALL
    SELECT 'BD-UPZ-208' AS parent_code, 'union' AS area_type, 'Gajirhat' AS name, 'BD-UNION-1892' AS code
  UNION ALL
    SELECT 'BD-UPZ-208' AS parent_code, 'union' AS area_type, 'Barakpur' AS name, 'BD-UNION-1893' AS code
  UNION ALL
    SELECT 'BD-UPZ-208' AS parent_code, 'union' AS area_type, 'Aronghata' AS name, 'BD-UNION-1894' AS code
  UNION ALL
    SELECT 'BD-UPZ-208' AS parent_code, 'union' AS area_type, 'Jogipol' AS name, 'BD-UNION-1895' AS code
  UNION ALL
    SELECT 'BD-UPZ-208' AS parent_code, 'union' AS area_type, 'Digholia' AS name, 'BD-UNION-1896' AS code
  UNION ALL
    SELECT 'BD-UPZ-209' AS parent_code, 'union' AS area_type, 'Aichgati' AS name, 'BD-UNION-1897' AS code
  UNION ALL
    SELECT 'BD-UPZ-209' AS parent_code, 'union' AS area_type, 'Srifoltola' AS name, 'BD-UNION-1898' AS code
  UNION ALL
    SELECT 'BD-UPZ-209' AS parent_code, 'union' AS area_type, 'Noihati' AS name, 'BD-UNION-1899' AS code
  UNION ALL
    SELECT 'BD-UPZ-209' AS parent_code, 'union' AS area_type, 'Tsb' AS name, 'BD-UNION-1900' AS code
  UNION ALL
    SELECT 'BD-UPZ-209' AS parent_code, 'union' AS area_type, 'Ghatvog' AS name, 'BD-UNION-1901' AS code
  UNION ALL
    SELECT 'BD-UPZ-210' AS parent_code, 'union' AS area_type, 'Terokhada' AS name, 'BD-UNION-1902' AS code
  UNION ALL
    SELECT 'BD-UPZ-210' AS parent_code, 'union' AS area_type, 'Chagladoho' AS name, 'BD-UNION-1903' AS code
  UNION ALL
    SELECT 'BD-UPZ-210' AS parent_code, 'union' AS area_type, 'Barasat' AS name, 'BD-UNION-1904' AS code
  UNION ALL
    SELECT 'BD-UPZ-210' AS parent_code, 'union' AS area_type, 'Sochiadaho' AS name, 'BD-UNION-1905' AS code
  UNION ALL
    SELECT 'BD-UPZ-210' AS parent_code, 'union' AS area_type, 'Modhupur' AS name, 'BD-UNION-1906' AS code
  UNION ALL
    SELECT 'BD-UPZ-210' AS parent_code, 'union' AS area_type, 'Ajgora' AS name, 'BD-UNION-1907' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Dumuria' AS name, 'BD-UNION-1908' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Magurghona' AS name, 'BD-UNION-1909' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Vandarpara' AS name, 'BD-UNION-1910' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Sahos' AS name, 'BD-UNION-1911' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Rudaghora' AS name, 'BD-UNION-1912' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Ghutudia' AS name, 'BD-UNION-1913' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Shovna' AS name, 'BD-UNION-1914' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Khornia' AS name, 'BD-UNION-1915' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Atlia' AS name, 'BD-UNION-1916' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Dhamalia' AS name, 'BD-UNION-1917' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Raghunathpur' AS name, 'BD-UNION-1918' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Rongpur' AS name, 'BD-UNION-1919' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Shorafpur' AS name, 'BD-UNION-1920' AS code
  UNION ALL
    SELECT 'BD-UPZ-211' AS parent_code, 'union' AS area_type, 'Magurkhali' AS name, 'BD-UNION-1921' AS code
  UNION ALL
    SELECT 'BD-UPZ-212' AS parent_code, 'union' AS area_type, 'Botiaghata' AS name, 'BD-UNION-1922' AS code
  UNION ALL
    SELECT 'BD-UPZ-212' AS parent_code, 'union' AS area_type, 'Amirpur' AS name, 'BD-UNION-1923' AS code
  UNION ALL
    SELECT 'BD-UPZ-212' AS parent_code, 'union' AS area_type, 'Gongarampur' AS name, 'BD-UNION-1924' AS code
  UNION ALL
    SELECT 'BD-UPZ-212' AS parent_code, 'union' AS area_type, 'Surkhali' AS name, 'BD-UNION-1925' AS code
  UNION ALL
    SELECT 'BD-UPZ-212' AS parent_code, 'union' AS area_type, 'Vandarkot' AS name, 'BD-UNION-1926' AS code
  UNION ALL
    SELECT 'BD-UPZ-212' AS parent_code, 'union' AS area_type, 'Baliadanga' AS name, 'BD-UNION-1927' AS code
  UNION ALL
    SELECT 'BD-UPZ-212' AS parent_code, 'union' AS area_type, 'Jolma' AS name, 'BD-UNION-1928' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Dakop' AS name, 'BD-UNION-1929' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Bajua' AS name, 'BD-UNION-1930' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Kamarkhola' AS name, 'BD-UNION-1931' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Tildanga' AS name, 'BD-UNION-1932' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Sutarkhali' AS name, 'BD-UNION-1933' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Laudoba' AS name, 'BD-UNION-1934' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Pankhali' AS name, 'BD-UNION-1935' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Banishanta' AS name, 'BD-UNION-1936' AS code
  UNION ALL
    SELECT 'BD-UPZ-213' AS parent_code, 'union' AS area_type, 'Koilashgonj' AS name, 'BD-UNION-1937' AS code
  UNION ALL
    SELECT 'BD-UPZ-214' AS parent_code, 'union' AS area_type, 'Koyra' AS name, 'BD-UNION-1938' AS code
  UNION ALL
    SELECT 'BD-UPZ-214' AS parent_code, 'union' AS area_type, 'Moharajpur' AS name, 'BD-UNION-1939' AS code
  UNION ALL
    SELECT 'BD-UPZ-214' AS parent_code, 'union' AS area_type, 'Moheswaripur' AS name, 'BD-UNION-1940' AS code
  UNION ALL
    SELECT 'BD-UPZ-214' AS parent_code, 'union' AS area_type, 'North Bedkashi' AS name, 'BD-UNION-1941' AS code
  UNION ALL
    SELECT 'BD-UPZ-214' AS parent_code, 'union' AS area_type, 'South Bedkashi' AS name, 'BD-UNION-1942' AS code
  UNION ALL
    SELECT 'BD-UPZ-214' AS parent_code, 'union' AS area_type, 'Amadi' AS name, 'BD-UNION-1943' AS code
  UNION ALL
    SELECT 'BD-UPZ-214' AS parent_code, 'union' AS area_type, 'Bagali' AS name, 'BD-UNION-1944' AS code
  UNION ALL
    SELECT 'BD-UPZ-215' AS parent_code, 'union' AS area_type, 'Betaga' AS name, 'BD-UNION-1945' AS code
  UNION ALL
    SELECT 'BD-UPZ-215' AS parent_code, 'union' AS area_type, 'Lakhpur' AS name, 'BD-UNION-1946' AS code
  UNION ALL
    SELECT 'BD-UPZ-215' AS parent_code, 'union' AS area_type, 'Fakirhat' AS name, 'BD-UNION-1947' AS code
  UNION ALL
    SELECT 'BD-UPZ-215' AS parent_code, 'union' AS area_type, 'Bahirdia-Mansa' AS name, 'BD-UNION-1948' AS code
  UNION ALL
    SELECT 'BD-UPZ-215' AS parent_code, 'union' AS area_type, 'Piljanga' AS name, 'BD-UNION-1949' AS code
  UNION ALL
    SELECT 'BD-UPZ-215' AS parent_code, 'union' AS area_type, 'Naldha-Mouvhog' AS name, 'BD-UNION-1950' AS code
  UNION ALL
    SELECT 'BD-UPZ-215' AS parent_code, 'union' AS area_type, 'Mulghar' AS name, 'BD-UNION-1951' AS code
  UNION ALL
    SELECT 'BD-UPZ-215' AS parent_code, 'union' AS area_type, 'Suvhadia' AS name, 'BD-UNION-1952' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Karapara' AS name, 'BD-UNION-1953' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Bamorta' AS name, 'BD-UNION-1954' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Gotapara' AS name, 'BD-UNION-1955' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Bishnapur' AS name, 'BD-UNION-1956' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Baruipara' AS name, 'BD-UNION-1957' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Jatharapur' AS name, 'BD-UNION-1958' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Shaitgomboj' AS name, 'BD-UNION-1959' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Khanpur' AS name, 'BD-UNION-1960' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Rakhalgachi' AS name, 'BD-UNION-1961' AS code
  UNION ALL
    SELECT 'BD-UPZ-216' AS parent_code, 'union' AS area_type, 'Dema' AS name, 'BD-UNION-1962' AS code
  UNION ALL
    SELECT 'BD-UPZ-217' AS parent_code, 'union' AS area_type, 'Udoypur' AS name, 'BD-UNION-1963' AS code
  UNION ALL
    SELECT 'BD-UPZ-217' AS parent_code, 'union' AS area_type, 'Chunkhola' AS name, 'BD-UNION-1964' AS code
  UNION ALL
    SELECT 'BD-UPZ-217' AS parent_code, 'union' AS area_type, 'Gangni' AS name, 'BD-UNION-1965' AS code
  UNION ALL
    SELECT 'BD-UPZ-217' AS parent_code, 'union' AS area_type, 'Kulia' AS name, 'BD-UNION-1966' AS code
  UNION ALL
    SELECT 'BD-UPZ-217' AS parent_code, 'union' AS area_type, 'Gaola' AS name, 'BD-UNION-1967' AS code
  UNION ALL
    SELECT 'BD-UPZ-217' AS parent_code, 'union' AS area_type, 'Kodalia' AS name, 'BD-UNION-1968' AS code
  UNION ALL
    SELECT 'BD-UPZ-217' AS parent_code, 'union' AS area_type, 'Atjuri' AS name, 'BD-UNION-1969' AS code
  UNION ALL
    SELECT 'BD-UPZ-218' AS parent_code, 'union' AS area_type, 'Dhanshagor' AS name, 'BD-UNION-1970' AS code
  UNION ALL
    SELECT 'BD-UPZ-218' AS parent_code, 'union' AS area_type, 'Khontakata' AS name, 'BD-UNION-1971' AS code
  UNION ALL
    SELECT 'BD-UPZ-218' AS parent_code, 'union' AS area_type, 'Rayenda' AS name, 'BD-UNION-1972' AS code
  UNION ALL
    SELECT 'BD-UPZ-218' AS parent_code, 'union' AS area_type, 'Southkhali' AS name, 'BD-UNION-1973' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Gouramva' AS name, 'BD-UNION-1974' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Uzzalkur' AS name, 'BD-UNION-1975' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Baintala' AS name, 'BD-UNION-1976' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Rampal' AS name, 'BD-UNION-1977' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Rajnagar' AS name, 'BD-UNION-1978' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Hurka' AS name, 'BD-UNION-1979' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Perikhali' AS name, 'BD-UNION-1980' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Vospatia' AS name, 'BD-UNION-1981' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Mollikerbar' AS name, 'BD-UNION-1982' AS code
  UNION ALL
    SELECT 'BD-UPZ-219' AS parent_code, 'union' AS area_type, 'Bastoli' AS name, 'BD-UNION-1983' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Teligati' AS name, 'BD-UNION-1984' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Panchakaran' AS name, 'BD-UNION-1985' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Putikhali' AS name, 'BD-UNION-1986' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Daibagnyahati' AS name, 'BD-UNION-1987' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Ramchandrapur' AS name, 'BD-UNION-1988' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Chingrakhali' AS name, 'BD-UNION-1989' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Jiudhara' AS name, 'BD-UNION-1990' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Hoglapasha' AS name, 'BD-UNION-1991' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Banagram' AS name, 'BD-UNION-1992' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Balaibunia' AS name, 'BD-UNION-1993' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Hoglabunia' AS name, 'BD-UNION-1994' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Baharbunia' AS name, 'BD-UNION-1995' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Morrelganj' AS name, 'BD-UNION-1996' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Khaulia' AS name, 'BD-UNION-1997' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Nishanbaria' AS name, 'BD-UNION-1998' AS code
  UNION ALL
    SELECT 'BD-UPZ-220' AS parent_code, 'union' AS area_type, 'Baraikhali' AS name, 'BD-UNION-1999' AS code
  UNION ALL
    SELECT 'BD-UPZ-221' AS parent_code, 'union' AS area_type, 'Gojalia' AS name, 'BD-UNION-2000' AS code
) AS v
INNER JOIN administrative_areas p ON p.code = v.parent_code
ON CONFLICT DO NOTHING;

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