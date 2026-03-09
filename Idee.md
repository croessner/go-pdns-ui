# Go-PDNS

# Grundlegendes

Go 1.26.x

HTMX

Pure API zu PowerDNS

Muss komplett OOP geschrieben sein mit Unit-Tests und Interfaces (wenn benötigt)

## Ziel

Eine Weboberflöche, mit der ich wieder bequem meine PowerDNS-Zonen administrieren kann.

## Features

Anmelden per hart-kodiertem User/Pass oder alternativ OIDC mit Access-Token und Refresh-Token. Infos dann über ID-Token.

### Domains

- Listen
- Hinzufügen
- Löschen mit Nachfrage

### Domain (Zone)

Alle Arten von Records sollen hinzugefügt werden können

Auch ändern und löschen

### DNSSEC aktivieren können

### Zone Templates

### Reverse-Zonen-Support für IPv4 und IPv6

### Eine Art Apply/Save - Mechanismus

Freies Editieren. Save für Einträge. Apply für ganze Zone.

SOA berücksichtigen

### Sonstiges

Alles, was dir einfällt, was die Benutzung angenehm macht. UI darf modern sein. Da gibt es etwas, was wie Waynland oder so heißt und DasyUI oder so. Findest du raus.  Ich benutze das schon bei Nauthilus.

Ich hätte auch gerne einen schaltbaren Dark-Mode.

UI darf Multi-Lingual sein. Da gibt es ein Package, dass erlaubt schöne JSON-Dateien für Sprache. Englisch und Deutsch wären für den Anfang okay.

Lizenz Apache-2
