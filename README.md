## Simple Program Workflow English:

**1. IP Collection:**

Retrieves recently reported IP addresses with an Abuse Confidence Score of 100 from AbuseIPDB.

AbuseIPDB is a global database for reporting and querying IP addresses in real time that have been 
associated with cyberattacks such as password brute-force attempts or spam. 
System administrators use this live data to identify suspicious IP addresses and protect their networks and user accounts 
against password-based attacks.

**2. Data Collection and Classification:**

Collects ASN, provider, hostname, location, IP type (Hosting, Business, Wireless, Residential), and proxy/VPN/Tor indicators.
Based on these and other characteristics, IP addresses are classified according to their anonymization methods and IP types.

Further classification is performed based on the assignment of IP addresses to specific providers and organizations. 
The IP addresses are checked against lists of ASNs and IP address ranges and assigned to categories such as Trusted Scanners,
trusted cloud providers (e.g., Azure, AWS, and Google Cloud), CDN, Bulletproof Hosting, and Grey Hosting.

Bulletproof Hosting refers to hosting services that deliberately tolerate illegal or malicious content and resist enforcement
actions or complaints, for example, those concerning copyright infringement. Data from sources such as Spamhaus.org is used to 
help identify such providers.

Legitimate organizations that scan the Internet exclusively for informational and research purposes are classified as 
Trusted Scanners. Since their activities are sometimes mistakenly reported as attacks, their IP addresses may also receive 
an Abuse Confidence Score of 100 and be included in the system.

IP addresses that cannot be clearly assigned to any of the aforementioned categories are classified as Grey Hosting. 
This category enables hosting providers that have not yet been clearly classified to be investigated in greater detail 
using the integrated ASN Research module.

**3. Storage and Visualization:**

Stores the results in SQLite and displays them in the Streamlit dashboard, including selected MITRE ATT&CK mappings such as 
Resource Development (TA0042), Reconnaissance (TA0043), and their associated sub-techniques.

**4. ASN Analysis:**

For ASN, IP, and provider research, RIPE Stat APIs (WHOIS, abuse-contact-finder, routing-status, prefix-count, network-info, 
and rpki-validation) and RDAP queries are used to retrieve registration data. Additional DNS queries (A, MX, PTR, and FCrDNS) 
are performed. The analysis also investigates whether providers accept cryptocurrency payments.

The final risk analysis is performed using the Gemini API with URL Context and Google Search.


**5. AI-Powered Risk Assessment:**

Gemini evaluates the collected information and generates a risk score, a risk classification, and an explanation based on 
positive and negative factors.

## Simple Program Workflow German:

**1. IP-Erfassung:** Ruft kürzlich gemeldete IP-Adressen mit einem Abuse Confidence Score von 100 von AbuseIPDB ab.
AbuseIPDB ist eine globale Datenbank zur Meldung und Abfrage von IP-Adressen in Echtzeit, die an Cyberangriffen wie Kennwort-Brute-Force-Versuchen 
oder Spam beteiligt sind. Systemadministratoren nutzen diese Live-Daten, um verdächtige IP-Adressen zu identifizieren und ihr 
Netzwerk sowie Benutzerkonten vor Kennwort-Angriffen zu schützen.

**2. Datenerfassung und Klassifizierung:** Erfasst ASN, Provider, Hostname, Standort, IP-Typ (Hosting, Business, Wireless, 
Residential) sowie Proxy-/VPN-/Tor-Indikatoren. Anhand dieser und weiterer Merkmale werden die IP-Adressen nach Anonymisierungsmethoden 
und IP-Typen klassifiziert.

Eine weitere Klassifizierung erfolgt anhand der Zuordnung zu bestimmten Providern und Organisationen. Dazu werden die IP-Adressen 
anhand von Listen mit ASNs und IP-Adressblöcken überprüft und Kategorien wie Trusted Scanner, vertrauenswürdige Cloud-Provider 
(z. B. Azure, AWS und Google Cloud), CDN, Bulletproof Hosting und Grey Hosting zugeordnet.

Bulletproof Hosting bezeichnet Hosting-Dienste, die illegale oder bösartige Inhalte bewusst tolerieren und sich behördlichen 
Maßnahmen oder Beschwerden, beispielsweise wegen Urheberrechtsverletzungen, widersetzen. Zur Identifizierung solcher Anbieter 
werden unter anderem Daten von Spamhaus.org verwendet.

Legitime Organisationen, die das Internet ausschließlich zu Informations- und Forschungszwecken scannen, werden als Trusted Scanner 
bezeichnet. Da deren Aktivitäten gelegentlich fälschlicherweise als Angriffe gemeldet werden, können ihre IP-Adressen ebenfalls 
einen Abuse Confidence Score von 100 erhalten und in das System aufgenommen werden.

IP-Adressen, die keiner der genannten Kategorien eindeutig zugeordnet werden können, werden als Grey Hosting klassifiziert. 
Diese Kategorie ermöglicht es, bislang nicht eindeutig eingestufte Hosting-Provider anschließend mit dem 
integrierten ASN-Research-Modul genauer zu untersuchen.


**3. Speicherung und Visualisierung:**  Speichert die Ergebnisse in SQLite und stellt sie im Streamlit-Dashboard dar, 
einschließlich ausgewählter MITRE-ATT&CK-Zuordnungen wie Resource Development (TA0042), und Reconnaissance (TA0043) und 
dazu gehörige Submethoden.

**4. ASN-Analyse:** Für die ASN, IP, Provider-Recherche werden RIPE-Stat-APIs (WHOIS, abuse-contact-finder, routing-status, 
prefix-count, network-info, rpki-validation) sowie RDAP-Abfragen zur Ermittlung von Registrierungsdaten verwendet. 
Ergänzend erfolgen DNS-Abfragen (A, MX, PTR, FCrDNS); Es wird auch untersucht ob Provider Coin Zahlungen akzeptiert. 
Es wir die abschließende Risikoanalyse wird mit der Gemini API unter Verwendung von URL Context und Google Search durchgeführt.

**5. KI-gestützte Risikobewertung:**  Gemini bewertet die gesammelten Informationen und erstellt einen Risikoscore, eine 
Risikoeinstufung sowie eine Begründung anhand positiver und negativer Faktoren.

## ASN- und IP-Analyse im Detail:

Für die detaillierte Analyse von ASNs, IP-Adressen und Hosting-Providern werden RIPE Stat APIs, RDAP, IANA und DNS-Abfragen verwendet. 
Die gesammelten Daten werden anschließend mit der Gemini API ausgewertet.

**RIPE Stat API**

RIPE Stat stellt Informationen über IP-Adressen, autonome Systeme (ASNs), Routing und Netzwerkregistrierungen bereit. 
Die Daten werden über HTTP-API-Abfragen abgerufen.

| API-Endpunkt | Zweck |
|---|---|
| `whois` | Ermittelt Registrierungs-, Organisations- und Netzwerkinformationen zu einer ASN oder IP-Adresse. |
| `abuse-contact-finder` | Ermittelt die zuständigen Abuse-Kontaktadressen eines Netzwerks. |
| `routing-status` | Liefert Informationen zum Routingstatus, zur Sichtbarkeit und zur Anzahl angekündigter Prefixes. |
| `prefix-count` | Zeigt die Entwicklung der angekündigten Prefix-Anzahl im Zeitverlauf. |
| `network-info` | Ermittelt das angekündigte Prefix und die Origin-ASN einer IP-Adresse. |
| `rpki-validation` | Überprüft, ob die Ankündigung eines Prefixes durch die angegebene Origin-ASN gemäß RPKI autorisiert ist. |

**RDAP und IANA**

**RDAP (Registration Data Access Protocol)** stellt strukturierte Registrierungsdaten zu ASNs und IP-Adressbereichen im JSON-Format bereit. 
Dazu gehören beispielsweise Organisationsinformationen, Netzwerkbereiche, Status sowie Registrierungs- und Änderungsdaten.

**IANA (Internet Assigned Numbers Authority)** wird verwendet, um über RDAP-Bootstrap-Dateien den zuständigen 
RDAP-Server für eine ASN oder IP-Adresse zu ermitteln.

- `asn.json`: Ermittelt den zuständigen RDAP-Server für eine ASN.
- `ipv4.json`: Ermittelt den zuständigen RDAP-Server für IPv4-Adressen.
- `ipv6.json`: Ermittelt den zuständigen RDAP-Server für IPv6-Adressen.

Anschließend werden die Registrierungsdaten direkt beim zuständigen RDAP-Server abgefragt.

**DNS-Abfragen**

Zur Untersuchung der Netzwerk- und Domainzugehörigkeit werden folgende DNS-Abfragen durchgeführt:

| Abfragetyp | Zweck |
|---|---|
| `A` | Ermittelt die IPv4-Adresse einer Domain. |
| `MX` | Ermittelt die zuständigen Mailserver einer Domain. |
| `PTR` | Ermittelt den Reverse-DNS-Hostnamen einer IP-Adresse. |
| `FCrDNS` | Überprüft, ob ein über PTR ermittelter Hostname wieder auf die ursprüngliche IP-Adresse verweist. |

**KI-gestützte Analyse mit Gemini**

Die gesammelten ASN-, Registrierungs-, Routing-, RPKI- und DNS-Daten werden zusammen mit der Homepage-URL des Hosting-Providers an die Gemini API übermittelt.

- **URL Context:** Ermöglicht die Analyse der angegebenen Homepage.
- **Google Search:** Ermöglicht zusätzliche Recherchen zu öffentlich verfügbaren Informationen über den Provider und seine Infrastruktur.

Gemini bewertet die gesammelten Informationen und erstellt eine Risikoeinstufung mit Risikoscore, positiven und negativen Faktoren sowie einer zusammenfassenden Begründung.

**Hinweis:** RPKI überprüft die Autorisierung von BGP-Routen und ist kein direkter Indikator dafür, ob eine IP-Adresse bösartig ist.



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
Berücksichtigt werden beispielsweise Resource Development (TA0042), und Reconnaissance (TA0043).
Die Zuordnung unterstützt die strukturierte Einordnung möglicher Bedrohungsszenarien und zeigt, welche IP-Adressen mit den
jeweiligen Kategorien verbunden sind. Die Zuordnung dient der Analyse und stellt für sich allein keinen Nachweis einer konkreten 
Angriffshandlung dar.

---

## `pages/hosting.py`

Diese Seite zeigt erkannte Cloud- und Grey-Hosting-IP-Adressen sowie die zugehörigen ASNs an. 
Unbekannte Hosting-Anbieter können gezielt ausgewählt und anhand ihrer Netzwerk- und Registrierungsdaten weiter 
untersucht werden. Die Ergebnisse umfassen Risikofaktoren, positive Indikatoren und eine Gesamtbewertung des jeweiligen Anbieters.
Dadurch unterstützt die Seite die Untersuchung potenziell missbräuchlich genutzter Hosting-Infrastrukturen.
