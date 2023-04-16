# Dokumentace projektu IPK2 - Varianta ZETA 2022/2023 #
## Jméno a příjmení: Rostislav Král
## Login: xkralr06 ##

---

## Základní informace:

#### Projekt používá:
- Překladač g++, standard C++20
- pcap.h
- Make
- Lze spustit pouze na linuxovém prostředí např. (Debian based, CentOS aj.)
- Má pouze jeden soubor se zdrojovým kódem
- Licence GPL3
- Testy jsou v podobě screenshotů ve složce tests
---
## Průběh programu
Program začíná parsováním argumentů z terminálu od uživatele knihovny ``getopt``,
kde se vyhodnocuje správný počet a jednotlivé omezení daného argumentu. Následně se
tvoří filter string na základě zadaných parametrů. Ošetří se případné chyby např.
s vybráním neexistující/jinak nevalidního network interfacu. Errory jsou vypisováný na
```stdin```. 

Program pracuje jak s IPv4 tak IPv6 adresami. Časová známka, velikost rámce, MAC adresa 
a typ packetu se parsuje ze struktury ```struct pcap_pkthdr```.
Poté na základě struktury ```struct ether_header``` a jejího datového člena
```ether_type``` zvolí zda se jedná o IPv4, IPv6 nebo ARP(Pouze IPv4) typ adresy.
U IPv4 a IPv6 se ještě rozhoduje ze struktury ```ip6_hdr``` nebo ```ip``` zda-li
nejde o TCP nebo UDP protokol, pokud ano, tak program přečte ze struktury ```tcphdr``` / ```udphdr```
port, na kterém byl packet uskutečněn.

Samotný výpis obsahu packetu obstarává funkce ```print_packet_data```, která
bere už vyextrahovaný payload a jeho délku a pak jej jen pomocí cyklů vypíše v
daném formátu.

---

## Testování

Testování bylo realizováno pomocí programu Wireshark, některé testy jsou
ve složce tests v podobě screenshotů. Např. ICMPv6, UDP, ARP atp.