-- 主機 × advisory × 嚴重度 × CVE（MLM 報表資料庫 reportdb）
-- systemerrata：該主機「可套用但尚未套用」的修補（依主機訂閱的通道內容計算）
-- errata.cve 為「; 」分隔字串（實測），也容許逗號，拆成一列一個 CVE；沒有 CVE 的 advisory 也保留（cve 顯示為空）
SELECT s.hostname                                   AS host,
       se.advisory_name                             AS advisory,
       se.advisory_type                             AS type,
       coalesce(nullif(e.severity, ''), '(未標)')   AS severity,
       trim(c.cve)                                  AS cve,
       e.synopsis                                   AS synopsis,
       e.issue_date::date                           AS issued
FROM systemerrata se
JOIN system s  ON s.system_id = se.system_id AND s.mgm_id = se.mgm_id
JOIN errata e  ON e.errata_id = se.errata_id AND e.mgm_id = se.mgm_id
LEFT JOIN LATERAL regexp_split_to_table(nullif(e.cve, ''), '\s*[;,]\s*') AS c(cve) ON true
ORDER BY CASE e.severity WHEN 'Critical' THEN 1 WHEN 'Important' THEN 2 WHEN 'Moderate' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END,
         s.hostname, se.advisory_name, cve;
