# Multi TCP TODO / Fragliche Punkte

Hinweis:
- Diese Liste sammelt Dinge, die fraglich sind oder verbessert werden koennen.
- Jeder Punkt nennt: Warum fraglich + was daran falsch sein koennte + Richtung der Loesung.


## 1) Timing / Handshake

1.1 Clock-Skew bei MultiStart
- Warum fraglich: start_at basiert auf der lokalen Uhr des Senders.
- Risiko: Receiver startet frueher/spaeter (Skew), Multi-Punch verfehlt sich.
- Idee: start_in (relative Sek.) statt absoluter Zeit; oder Offset aus Relay (time_offset) fuer MultiStart nutzen; oder start_at neu berechnen bei Empfang, wenn bereits in der Vergangenheit.

1.2 start_at kann in der Vergangenheit liegen
- Warum fraglich: MultiPlan + Aufbau der Conns dauert; start_at kann schon vorbei sein.
- Risiko: sofortige oder asynchrone Starts, weniger koordinierter Punch.
- Idee: start_at auf min(now + delta) clampen, oder neuen Start anfragen, wenn zu alt.

1.3 local_ports nur nach Anzahl validiert
- Warum fraglich: Duplikate oder 0/ungueltige Ports sind moeglich.
- Risiko: Bind-Kollisionen, conn_id -> port Mapping wird unklar.
- Idee: local_ports auf >0, eindeutig, im Portbereich validieren; sonst Handshake abbrechen.


## 2) NAT / Prediction

2.1 Per-Port NAT-Analyse nicht wirklich pro Port
- Warum fraglich: Server nutzt dieselben Probes fuer jedes local_port.
- Risiko: Mapping je local_port kann anders sein, Analyse ist dann falsch.
- Idee: Probes nach local_port gruppieren; pro Gruppe eigene Analyse; fallback global nur bei zu wenig Daten.

2.2 External-only Mode: gleiche Prediction fuer alle Ports
- Warum fraglich: Wenn Ports in Clustern streuen, mean fuer alle Ports ungenau.
- Risiko: Scan-Range pro Conn wird zu eng.
- Idee: per-port Analysis auch im external mode, sofern genug Probes vorliegen.

2.3 scan_budget kann Scan-Range zu stark beschneiden
- Warum fraglich: Bei vielen Conns werden Kandidaten stark gekappt.
- Risiko: Erfolgsrate sinkt, ohne dass der Nutzer es merkt.
- Idee: Logging/Warning, wenn Kandidaten pro Conn gekuerzt wurden; optional Mindestbudget pro Conn.


## 3) Transfer Robustness

3.1 Kein per-Chunk Retry-Limit
- Warum fraglich: Ein Chunk kann endlos requeued werden.
- Risiko: endlose Loops, Traffic-Explosion bei schlechten Verbindungen.
- Idee: retry_count pro chunk_id fuehren und nach N Versuchen abbrechen.

3.2 Requeue erzeugt Duplikate
- Warum fraglich: Derselbe chunk_id kann mehrfach in der Queue landen.
- Risiko: zusaetzliche Sends und Acks, unnnoetiger Overhead.
- Idee: In-Flight/Pending Zustand pro chunk_id (bitset oder map), requeue nur wenn nicht bereits pending.

3.3 Invalid chunk length fuehrt sofort zum Abbruch
- Warum fraglich: Ein einzelner kaputter Header killt die Conn.
- Risiko: Verbindung stirbt, obwohl nur ein Header defekt war.
- Idee: Wenn len im sicheren Bereich ist, Daten verwerfen + NACK statt harter Abbruch; aber nur begrenzt (DoS-Schutz).

3.4 Bad-Chunk Decay (Hybrid) ist fest verdrahtet
- Warum fraglich: 2 gute Chunks -> 1 bad weniger passt nicht immer.
- Risiko: Zu aggressiv oder zu locker je nach Netzwerk.
- Idee: Parameter fuer Decay/Limit (CLI oder config) oder Zeit-basierte Decay.

3.5 Chunk ACK Timeout vs Stream-Abbruch
- Warum fraglich: Bei ACK-Delay wird der Stream als Fehler gewertet.
- Risiko: Conn stirbt zu schnell, obwohl Daten durchgehen.
- Idee: Pro-Chunk Timeout + N Wiederholungen, bevor der Stream aufgegeben wird.


## 4) Performance / Ressourcen

4.1 received_flags Speicherbedarf
- Warum fraglich: Vec<AtomicBool> ist O(chunks); bei sehr grossen Dateien wird das gross.
- Risiko: hoher RAM-Verbrauch, ggf. OOM.
- Idee: Bitset/BitVec; oder Chunkgroesse minimal/auto anheben.

4.2 Random-Access I/O bei vielen Conns
- Warum fraglich: Viele Writes auf unterschiedliche Offsets erzeugen I/O-Seek-Overhead.
- Risiko: Durchsatz sinkt auf langsamen Disks.
- Idee: Groessere Chunks, optional I/O Worker mit Write-Queue oder Mmap.


## 5) UX / Dokumentation / Tests

5.1 Strict-All-Conns Verhalten
- Warum fraglich: Transfer bricht komplett ab, wenn nur 1 Conn fehlt.
- Risiko: Erfolgsrate sinkt bei schwierigen NATs.
- Idee: Optionaler Flag fuer strict vs flexible (bereits angedacht), in README klar hervorheben.

5.2 Bad-Chunk Limit und Decay in Logs sichtbar
- Warum fraglich: Debugging schwer, wenn nicht klar ist, warum eine Conn stirbt.
- Risiko: Nutzer kann Verhalten nicht gut nachvollziehen.
- Idee: Log beim Decay/bei Conn-Kill mit summary.

5.3 Tests fuer Fehlerfaelle fehlen
- Warum fraglich: Multi-Conn, Requeue, CRC32, NACK usw. sind fehleranfaellig.
- Risiko: Regressionen bleiben unbemerkt.
- Idee: Lokale Tests fuer Abbruch einer Conn, CRC32 mismatch, retry limits, scan_budget.
