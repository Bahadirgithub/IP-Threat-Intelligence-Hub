## Simple Program Workflow

1. **IP Collection:** Retrieves recently reported IP addresses with an Abuse Confidence Score of 100 from AbuseIPDB.
2. **Enrichment & Classification:** Collects ASN, provider, location, IP type, and proxy/VPN/Tor indicators. 
IPs are checked against allowlists and classified into cloud, CDN, Bulletproof Hosting, Grey Hosting, and anonymization categories.
3. **Storage & Visualization:** Stores the results in SQLite and displays them in the Streamlit dashboard, 
including selected MITRE ATT&CK mappings.
4. **ASN Research:** Selected hosting providers are investigated using WHOIS/RDAP, DNS, routing, RPKI, and prefix-history data.
5. **AI Risk Assessment:** Gemini evaluates the collected evidence and generates a risk score, verdict, 
and supporting positive and negative factors.



# ThreatWatch – Modulbeschreibungen

---

## `ingestion.py`

Dieses Modul erfasst über AbuseIPDB bekannte IP-Adressen, die innerhalb der letzten 24 Stunden mit einem 
Abuse Confidence Score von 100 gemeldet wurden. Dadurch werden IP-Adressen mit aktuellen Missbrauchsmeldungen für die 
weitere Sicherheitsanalyse ausgewählt.

---

## `enrichment.py`

Dieses Modul ergänzt IP-Adressen mithilfe der ProxyCheck.io-v3-API um Netzwerk- und Reputationsinformationen. 
Dazu gehören ASN, Hostname, Provider, Standort und Hinweise auf Proxy-, VPN- oder Tor-Nutzung sowie 
bekannte kompromittierte Systeme. Diese Informationen dienen zur Erkennung und Einordnung potenziell verdächtiger IP-Adressen.

---

## `whitelist.py` & `whitelist_data.py`

Diese Module prüfen IP-Adressen anhand vertrauenswürdiger ASNs, einzelner IP-Adressen und IP-Adressbereiche. 
Erkannte Freigaben werden genutzt, um bekannte legitime Systeme wie vertrauenswürdige Scanner von weiteren Analysen auszunehmen.
Dadurch können Fehlalarme bei der Erkennung potenzieller Bedrohungen reduziert werden.

---

## `cross_check.py`

Dieses Modul überprüft die Klassifizierung von IP-Adressen mithilfe zusätzlicher Netzwerkdaten von ipapi.is. 
Wird eine vermeintliche Business- oder Residential-IP als Rechenzentrumsadresse erkannt, wird sie als `Hosting` klassifiziert. 
Mobile IP-Adressen werden entsprechend als `Wireless` eingestuft.
Dadurch wird die Erkennung von Hosting-Infrastrukturen verbessert.

---

## `cloud_check.py`

Dieses Modul identifiziert IP-Adressen großer Cloud-Anbieter wie AWS, Azure und Google Cloud sowie von Content Delivery Networks (CDNs). 
Dafür werden IP-Adressen mit bekannten Netzwerkpräfixen aus lokalen Datenbeständen verglichen.
Zusätzlich werden ASNs bekannter Bulletproof-Hosting-Anbieter geprüft. Die Ergebnisse helfen dabei, unterschiedliche 
Hosting-Infrastrukturen zu erkennen und für die weitere Sicherheitsanalyse einzuordnen.

---

## `grey_check.py`

Dieses Modul identifiziert IP-Adressen, die als Hosting klassifiziert wurden, aber keinem bekannten Cloud-Anbieter, CDN oder erfassten
Bulletproof-Hosting-ASN zugeordnet werden können. Diese Adressen werden als Grey Hosting zusammengefasst und nach ASN gruppiert. 
Dadurch lassen sich unbekannte Hosting-Anbieter erkennen, die für eine vertiefte Risikoanalyse infrage kommen.

---

## `anonymization_check.py`

Dieses Modul klassifiziert IP-Adressen anhand ihrer Anonymisierungseigenschaften in sechs Kategorien: Tor Exit Node, Residential Proxy, 
Public Proxy, Self-hosted Proxy, Commercial VPN und Private VPN. Als Grundlage dienen Erkennungsmerkmale wie `proxy`, `vpn` und `tor` 
sowie IP-Typ und Operator-Name. Die Ergebnisse unterstützen die Identifikation von Infrastruktur, die zur Verschleierung der tatsächlichen 
Herkunft von Netzwerkverbindungen genutzt werden kann.

---

## `database.py`

Dieses Modul speichert die erfassten IP-Adressen und Analyseergebnisse in der SQLite-Datenbank `threat_intel.db`. 
Die Daten werden nach Kategorien wie allgemeine Erkennungen, vertrauenswürdige IP-Adressen, Cloud-Anbieter, CDNs und Grey Hosting verwaltet. 
Dadurch können Ergebnisse für spätere Untersuchungen und Vergleiche abgerufen werden.

---

## `provider_agent.py`

Dieses Modul untersucht ASNs und Hosting-Anbieter anhand technischer Netzwerk- und Registrierungsdaten.
Dabei werden unter anderem WHOIS- und RDAP-Einträge, Abuse-Kontakte, DNS-Auflösungen, Routing-Informationen, RPKI-Validierungen 
und die Entwicklung angekündigter IP-Präfixe ausgewertet. 
Zusätzlich werden Reverse-DNS-Einträge und verfügbare Informationen zur Website des Anbieters berücksichtigt.
Gemini bewertet die gesammelten Informationen und erstellt eine strukturierte Einschätzung mit Risikofaktoren, 
positiven Indikatoren und einem Gesamtrisiko.

---

## `microservice.py`

Dieses Modul ermöglicht die Untersuchung von ASNs über eine HTTP-Schnittstelle.
Dadurch können ausgewählte Hosting-Anbieter gezielt analysiert werden, ohne die gesamte IP-Klassifizierung erneut auszuführen. 
Die Ergebnisse umfassen die ermittelten Netzwerkmerkmale und die zugehörige Risikobewertung.

---

## `app.py`

Dieses Modul stellt die erfassten IP-Adressen und Analyseergebnisse übersichtlich dar. 
Die IP-Adressen werden anhand ihrer Netzwerkmerkmale geprüft und Kategorien wie Wireless, Cloud, CDN, Bulletproof Hosting 
und Grey Hosting zugeordnet. Dadurch können potenziell verdächtige Systeme erkannt und für eine detailliertere
Sicherheitsuntersuchung ausgewählt werden.

---

## `pages/mitre_attack.py`

Diese Seite ordnet ausgewählte Analyseergebnisse den relevanten Taktiken des MITRE ATT&CK Frameworks zu. 
Berücksichtigt werden beispielsweise Resource Development (TA0042), Command and Control (TA0011) und Reconnaissance (TA0043).
Die Zuordnung unterstützt die strukturierte Einordnung möglicher Bedrohungsszenarien und zeigt, welche IP-Adressen mit den
jeweiligen Kategorien verbunden sind. Die Zuordnung dient der Analyse und stellt für sich allein keinen Nachweis einer konkreten 
Angriffshandlung dar.

---

## `pages/hosting.py`

Diese Seite zeigt erkannte Cloud- und Grey-Hosting-IP-Adressen sowie die zugehörigen ASNs an. 
Unbekannte Hosting-Anbieter können gezielt ausgewählt und anhand ihrer Netzwerk- und Registrierungsdaten weiter 
untersucht werden. Die Ergebnisse umfassen Risikofaktoren, positive Indikatoren und eine Gesamtbewertung des jeweiligen Anbieters.
Dadurch unterstützt die Seite die Untersuchung potenziell missbräuchlich genutzter Hosting-Infrastrukturen.