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