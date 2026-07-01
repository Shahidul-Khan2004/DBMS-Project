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