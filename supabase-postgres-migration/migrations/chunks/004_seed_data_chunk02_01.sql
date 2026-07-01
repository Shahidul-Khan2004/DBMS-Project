-- from 22_seed_administrative_areas.sql
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