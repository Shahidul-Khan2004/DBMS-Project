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