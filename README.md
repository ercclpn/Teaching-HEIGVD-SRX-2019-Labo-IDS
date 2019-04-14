# Teaching-HEIGVD-SRX-2019-Laboratoire-IDS
Auteur : Mercier Jordan, Polier Florian, Tran Eric

**ATTENTION : Commencez par créer un Fork de ce repo et travaillez sur votre fork.**

Clonez le repo sur votre machine. Vous pouvez répondre aux questions en modifiant directement votre clone du README.md ou avec un fichier pdf que vous pourrez uploader sur votre fork.

**Le rendu consiste simplement à répondre à toutes les questions clairement identifiées dans le text avec la mention "Question" et à les accompagner avec des captures. Le rendu doit se faire par une "pull request". Envoyer également le hash du dernier commit et votre username GitHub par email au professeur et à l'assistant**

## Table de matières

[Introduction](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Laboratoire-IDS#introduction)

[Echéance](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Laboratoire-IDS#echéance)

[Configuration du réseau](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Laboratoire-IDS#configuration-du-réseau-sur-virtualbox)

[Installation de Snort](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Laboratoire-IDS#installation-de-snort-sur-linux)

[Essayer Snort](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Laboratoire-IDS#essayer-snort)

[Utilisation comme IDS](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Laboratoire-IDS#utilisation-comme-un-ids)

[Ecriture de règles](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Laboratoire-IDS#ecriture-de-règles)

[Travail à effectuer](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Laboratoire-IDS#exercises)


## Echéance 

Ce travail devra être rendu le dimanche après la fin de la 2ème séance de laboratoire, soit au plus tard, **le 14 avril 2019, à 23h.**


## Introduction

Dans ce travail de laboratoire, vous allez explorer un système de detection contre les intrusions (IDS) dont l'utilisation es très répandue grace au fait qu'il est gratuit et open source. Il s'appelle [Snort](https://www.snort.org). Il existe des versions de Snort pour Linux et pour Windows.

### Les systèmes de detection d'intrusion

Un IDS peut "écouter" tout le traffic de la partie du réseau où il est installé. Sur la base d'une liste de règles, il déclenche des actions sur des paquets qui correspondent à la description de la règle.

Un exemple de règle pourrait être, en language commun : "donner une alerte pour tous les paquets envoyés par le port http à un serveur web dans le réseau, qui contiennent le string 'cmd.exe'". En on peut trouver des règles très similaires dans les règles par défaut de Snort. Elles permettent de détecter, par exemple, si un attaquant essaie d'executer un shell de commandes sur un serveur Web tournant sur Windows. On verra plus tard à quoi ressemblent ces règles.

Snort est un IDS très puissant. Il est gratuit pour l'utilisation personnelle et en entreprise, où il est très utilisé aussi pour la simple raison qu'il est l'un des plus efficaces systèmes IDS.

Snort peut être exécuté comme un logiciel indépendant sur une machine ou comme un service qui tourne après chaque démarrage. Si vous voulez qu'il protège votre réseau, fonctionnant comme un IPS, il faudra l'installer "in-line" avec votre connexion Internet. 

Par exemple, pour une petite entreprise avec un accès Internet avec un modem simple et un switch interconnectant une dizaine d'ordinateurs de bureau, il faudra utiliser une nouvelle machine executant Snort et placée entre le modem et le switch. 


## Matériel

Vous avez besoin de votre ordinateur avec VirtualBox et une VM Kali Linux. Vous trouverez un fichier OVA pour la dernière version de Kali sur `//eistore1/cours/iict/Laboratoires/SRX/Kali` si vous en avez besoin.


## Configuration du réseau sur VirtualBox

Votre VM fonctionnera comme IDS pour "protéger" votre machine hôte (par exemple, si vous faites tourner VirtualBox sur une machine Windows, Snort sera utilisé pour capturer le trafic de Windows vers l'Internet).

Pour cela, il faudra configurer une réseau de la VM en mode "bridge" et activer l'option "Promiscuous Mode" dans les paramètres avancés de l'interface. Le mode bridge dans l'école ne vous permet pas d'accéder à l'Internet depuis votre VM. Vous pouvez donc rajouter une deuxième interface réseau à votre Kali configurée comme NAT. La connexion Internet est indispensable pour installer Snort mais pas vraiment nécessaire pour les manipulations du travail pratique.

Pour les captures avec Snort, assurez-vous de toujours indiquer la bonne interface dans la ligne de commandes, donc, l'interface configurée en mode promiscuous.

![Topologie du réseau virtualisé](images/Snort_Kali.png)


## Installation de Snort sur Linux

On va installer Snort sur Kali Linux. Si vous avez déjà une VM Kali, vous pouvez l'utiliser. Sinon, vous avez la possibilité de copier celle sur `eistore`.

La manière la plus simple c'est de d'installer Snort en ligne de commandes. Il suffit d'utiliser la commande suivante :

```
sudo apt update && apt install snort
```

Ceci télécharge et installe la version la plus récente de Snort.

Vers la fin de l'installation, on vous demande de fournir l'adresse de votre réseau HOME. Il s'agit du réseau que vous voulez protéger. Cela sert à configurer certaines variables pour Snort. Pour les manipulations de ce laboratoire, vous pouvez donner n'importe quelle adresse comme réponse.


## Essayer Snort

Une fois installé, vous pouvez lancer Snort comme un simple "sniffer". Pourtant, ceci capture tous les paquets, ce qui peut produire des fichiers de capture énormes si vous demandez de les journaliser. Il est beaucoup plus efficace d'utiliser des règles pour définir quel type de trafic est intéressant et laisser Snort ignorer le reste.

Snort se comporte de différentes manières en fonction des options que vous passez en ligne de commande au démarrage. Vous pouvez voir la grande liste d'options avec la commande suivante :

```
snort --help
```

On va commencer par observer tout simplement les entêtes des paquets IP utilisant la commande :

```
snort -v -i eth0
```

**ATTENTION : assurez-vous de bien choisir l'interface qui se trouve en mode bridge/promiscuous. Elle n'est peut-être pas eth0 chez-vous!**

Snort s'execute donc et montre sur l'écran tous les entêtes des paquets IP qui traversent l'interface eth0. Cette interface est connectée à l'interface réseau de votre machine hôte à travers le bridge de VirtualBox.

Pour arrêter Snort, il suffit d'utiliser `CTRL-C`.

## Utilisation comme un IDS

Pour enregistrer seulement les alertes et pas tout le trafic, on execute Snort en mode IDS. Il faudra donc spécifier un fichier contenant des règles. 

Il faut noter que `/etc/snort/snort.config` contient déjà des références aux fichiers de règles disponibles avec l'installation par défaut. Si on veut tester Snort avec des règles simples, on peut créer un fichier de config personnalisé (par exemple `mysnort.conf`) et importer un seul fichier de règles utilisant la directive "include".

Les fichiers de règles sont normalement stockes dans le repertoire `/etc/snort/rules/`, mais en fait un fichier de config et les fichiers de règles peuvent se trouver dans n'importe quel repertoire. 

Par exemple, créez un fichier de config `mysnort.conf` dans le repertoire `/etc/snort` avec le contenu suivant :

```
include /etc/snort/rules/icmp2.rules
```

Ensuite, créez le fichier de règles `icmp2.rules` dans le repertoire `/etc/snort/rules/` et rajoutez dans ce fichier le contenu suivant :

`alert icmp any any -> any any (msg:"ICMP Packet"; sid:4000001; rev:3;)`

On peut maintenant executer la commande :

```
snort -c /etc/snort/mysnort.conf
```

Vous pouvez maintenant faire quelques pings depuis votre hôte et regarder les résultas dans le fichier d'alertes contenu dans le repertoire `/var/log/snort/`. 


## Ecriture de règles

Snort permet l'écriture de règles qui décrivent des tentatives de exploitation de vulnérabilités bien connues. Les règles Snort prennent en charge à la fois, l'analyse de protocoles et la recherche et identification de contenu.

Il y a deux principes de base à respecter :

* Une règle doit être entièrement contenue dans une seule ligne
* Les règles sont divisées en deux sections logiques : (1) l'entête et (2) les options.

L'entête de la règle contient l'action de la règle, le protocole, les adresses source et destination, et les ports source et destination.

L'option contient des messages d'alerte et de l'information concernant les parties du paquet dont le contenu doit être analysé. Par exemple:

```
alert tcp any any -> 192.168.1.0/24 111 (content:"|00 01 86 a5|"; msg: "mountd access";)
```

Cette règle décrit une alerte générée quand Snort trouve un paquet avec tous les attributs suivants :

* C'est un paquet TCP
* Emis depuis n'importe quelle adresse et depuis n'importe quel port
* A destination du réseau identifié par l'adresse 192.168.1.0/24 sur le port 111

Le text jusqu'au premier parenthèse est l'entête de la règle. 

```
alert tcp any any -> 192.168.1.0/24 111
```

Les parties entre parenthèses sont les options de la règle:

```
(content:"|00 01 86 a5|"; msg: "mountd access";)
```

Les options peuvent apparaître une ou plusieurs fois. Par exemple :

```
alert tcp any any -> any 21 (content:"site exec"; content:"%"; msg:"site
exec buffer overflow attempt";)
```

La clé "content" apparait deux fois parce que les deux strings qui doivent être détectés n'apparaissent pas concaténés dans le paquet mais à des endroits différents. Pour que la règle soit déclenchée, il faut que le paquet contienne **les deux strings** "site exec" et "%". 

Les éléments dans les options d'une règle sont traitées comme un AND logique. La liste complète de règles sont traitées comme une succession de OR.

## Informations de base pour le règles

### Actions :

```
alert tcp any any -> any any (msg:"My Name!"; content:"Skon"; sid:1000001; rev:1;)
```

L'entête contient l'information qui décrit le "qui", le "où" et le "quoi" du paquet. Ça décrit aussi ce qui doit arriver quand un paquet correspond à tous les contenus dans la règle.

Le premier champ dans le règle c'est l'action. L'action dit à Snort ce qui doit être fait quand il trouve un paquet qui correspond à la règle. Il y a six actions :

* alert - générer une alerte et écrire le paquet dans le journal
* log - écrire le paquet dans le journal
* pass - ignorer le paquet
* drop - bloquer le paquet et l'ajouter au journal
* reject - bloquer le paquet, l'ajouter au journal et envoyer un `TCP reset` si le protocole est TCP ou un `ICMP port unreachable` si le protocole est UDP
* sdrop - bloquer le paquet sans écriture dans le journal

### Protocoles :

Le champ suivant c'est le protocole. Il y a trois protocoles IP qui peuvent être analysez par Snort : TCP, UDP et ICMP.


### Adresses IP :

La section suivante traite les adresses IP et les numéros de port. Le mot `any` peut être utilisé pour définir "n'import quelle adresse". On peut utiliser l'adresse d'une seule machine ou un block avec la notation CIDR. 

Un opérateur de négation peut être appliqué aux adresses IP. Cet opérateur indique à Snort d'identifier toutes les adresses IP sauf celle indiquée. L'opérateur de négation est le `!`.

Par exemple, la règle du premier exemple peut être modifiée pour alerter pour le trafic dont l'origine est à l'extérieur du réseau :

```
alert tcp !192.168.1.0/24 any -> 192.168.1.0/24 111
(content: "|00 01 86 a5|"; msg: "external mountd access";)
```

### Numéros de Port :

Les ports peuvent être spécifiés de différentes manières, y-compris `any`, une définition numérique unique, une plage de ports ou une négation.

Les plages de ports utilisent l'opérateur `:`, qui peut être utilisé de différentes manières aussi :

```
log udp any any -> 192.168.1.0/24 1:1024
```

Journaliser le traffic UDP venant d'un port compris entre 1 et 1024.

--

```
log tcp any any -> 192.168.1.0/24 :6000
```

Journaliser le traffic TCP venant d'un port plus bas ou égal à 6000.

--

```
log tcp any :1024 -> 192.168.1.0/24 500:
```

Journaliser le traffic TCP venant d'un port privilégié (bien connu) plus grand ou égal à 500 mais jusqu'au port 1024.


### Opérateur de direction

L'opérateur de direction `->`indique l'orientation ou la "direction" du trafique. 

Il y a aussi un opérateur bidirectionnel, indiqué avec le symbole `<>`, utile pour analyser les deux côtés de la conversation. Par exemple un échange telnet :

```
log 192.168.1.0/24 any <> 192.168.1.0/24 23
```

## Alertes et logs Snort

Si Snort détecte un paquet qui correspond à une règle, il envoie un message d'alerte ou il journalise le message. Les alertes peuvent être envoyées au syslog, journalisées dans un fichier text d'alertes ou affichées directement à l'écran.

Le système envoie **les alertes vers le syslog** et il peut en option envoyer **les paquets "offensifs" vers une structure de repertoires**.

Les alertes sont journalisées via syslog dans le fichier `/var/log/snort/alerts`. Toute alerte se trouvant dans ce fichier aura son paquet correspondant dans le même repertoire, mais sous le fichier snort.log.xxxxxxxxxx où xxxxxxxxxx est l'heure Unix du commencement du journal.

Avec la règle suivante :

```
alert tcp any any -> 192.168.1.0/24 111
(content:"|00 01 86 a5|"; msg: "mountd access";)
```

un message d'alerte est envoyé à syslog avec l'information "mountd access". Ce message est enregistré dans /var/log/snort/alerts et le vrai paquet responsable de l'alerte se trouvera dans un fichier dont le nom sera /var/log/snort/snort.log.xxxxxxxxxx.

Les fichiers log sont des fichiers binaires enregistrés en format pcap. Vous pouvez les ouvrir avec Wireshark ou les diriger directement sur la console avec la commande suivante :

```
tcpdump -r /var/log/snort/snort.log.xxxxxxxxxx
```

Vous pouvez aussi utiliser des captures Wireshark ou des fichiers snort.log.xxxxxxxxx comme source d'analyse por Snort.

## Exercises

**Réaliser des captures d'écran des exercices suivants et les ajouter à vos réponses.**

### Trouver votre nom :

Considérer la règle simple suivante:

alert tcp any any -> any any (msg:"Mon nom!"; content:"Rubinstein"; sid:4000015; rev:1;)

**Question 1: Qu'est-ce qu'elle fait la règle et comment ça fonctionne ?**

---

**Reponse :**  
Elle log une alerte quand il y a une communication tcp de n'importe quelle source vers n'importe quelle destination mais le paquet doit contenir dans ses data, un champs msg "Mon nom!" et un champs content avec la chaine "Rubinstein". Cette règle est identifiée avec l'id "4000015" et il s'agit de la première version de la règle. (rev:1).

---

Utiliser un éditeur et créer un fichier `myrules.rules` sur votre répertoire home. Rajouter une règle comme celle montrée avant mais avec votre nom ou un mot clé de votre préférence. Lancer snort avec la commande suivante :

```
sudo snort -c myrules.rules -i eth0
```

**Question 2: Que voyez-vous quand le logiciel est lancé ? Qu'est-ce que ça vaut dire ?**

---

**Reponse :**  
On voit l'initialisation de snort (statistique, etc...) et le warning :No preprocessors configured for policy 0.

![image](images/snort_init_part1.PNG)
![image](images/snort_init_part2.PNG)
---

Aller à un site web contenant votre nom ou votre mot clé que vous avez choisi dans son text (il faudra chercher un peu pour trouver un site en http...). Ensuite, arrêter Snort avec `CTRL-C`.

**Question 3: Que voyez-vous ?**

---

**Reponse :**  
Je vois les alertes suivantes:
```
[**] [1:4000015:3] text message [**]
[Priority: 0] 
04/09-15:48:45.285322 128.65.195.22:80 -> 10.192.91.110:55730
TCP TTL:53 TOS:0x0 ID:69 IpLen:20 DgmLen:227 DF
***AP*** Seq: 0xCD5EEAE6  Ack: 0x3496644E  Win: 0xF5  TcpLen: 20
```

---

Aller au répertoire /var/log/snort. Ouvrir le fichier `alert`. Vérifier qu'il y ait des alertes pour votre nom.

**Question 4: A quoi ressemble l'alerte ? Qu'est-ce que chaque champ veut dire ?**

---

**Reponse :**  

Le premier nombre est le Generator ID, cela nous donne quel est le sous-système de snort qui a généré l'alerte.  
Le deuxième nombre est le Snort ID, par conséquent l'ID de notre règle.  
Le troisième nombre est l'ID de la révision.  
Le `text message` correspond au type d'alerte.  
La priorité de l'alerte, ici 0.  
Nous avons ensuite le timestamp, l'ip source ainsi que le port, l'ip de destination ainsi que le port.  
Nous pouvons voir que la requête est de type TCP avec un time to live de 53, un type of service de 0x0, le header de l'ip est de 20bits, la taille du datagramme est de 227, le paquet n'est pas fragmenté.  
Nous avons ensuite une séquence avec le N° 0xCD5EEAE6 et le numéro de l'ACK N° 0x3496644E, la taille de la fenêtre qui est de 0xF5, puis la longueur du segment tcp qui est de 20bits.  

---


--

### Detecter une visite à Wikipedia

Ecrire une règle qui journalise (sans alerter) un message à chaque fois que Wikipedia est visité **DEPUIS VOTRE** station. **Ne pas utiliser une règle qui détecte un string ou du contenu**.

**Question 5: Quelle est votre règle ? Où le message a-t'il été journalisé ? Qu'est-ce qui a été journalisé ?**

---

**Reponse :**  
Quelle est votre règle ? 
```bash
log tcp any any -> 91.198.174.192 443 (msg:"ACCESS TO WIKIPEDIA";sid:4000015;rev:3;)
```

Où le message a-t'il été journalisé ?
Le message a été journalisé dans le fichier se trouvant dans /var/log/snort/snort.log.xxxxyyyyy

Qu'est-ce qui a été journalisé ?  
La banner de snort.  
Des informations sur chaque trame qui concerne la règle ainsi que toutes les infos du paquet tcp.  
Le temps d'éxecution ainsi que le nombre de paquet traités par snort.  
Des statistiques sur les input/output et sur la mémoire.  
Le nombre de paqeuts traités pour chaque protocole.  

---

--

### Detecter un ping d'un autre système

Ecrire une règle qui alerte à chaque fois que votre système reçoit un ping depuis une autre machine. Assurez-vous que **ça n'alerte pas** quand c'est vous qui envoyez le ping vers un autre système !

**Question 6: Quelle est votre règle ? Comment avez-vous fait pour que ça identifie seulement les pings entrants ? Où le message a-t'il été journalisé ? Qu'est-ce qui a été journalisé ?**

---

**Reponse :**  ^
```bash
alert icmp any any -> 192.168.0.164 any (msg:"Ping entrant";sid:4000016;rev:1;)
```
![image](images/Ping_Entrant.PNG)

---

--

### Detecter les ping dans les deux sens

Modifier votre règle pour que les pings soient détectés dans les deux sens.

**Question 7: Qu'est-ce que vous avez modifié pour que la règle détecte maintenant le trafic dans les deux senses ?**

---

**Reponse :**  
```bash
alert icmp any any <> 192.168.0.164 any (msg:"Ping detection";sid:4000016;rev:1;)
```
Il suffit de modifier la direction de détection de la règle (<>).

![image](images/Ping_Entrant_Sortant.PNG)

---


--

### Detecter une tentative de login SSH

Essayer d'écrire une règle qui Alerte qu'une tentative de session SSH a été faite depuis la machine d'un voisin. Si vous avez besoin de plus d'information sur ce qui décrit cette tentative (adresses, ports, protocoles), servez-vous de Wireshark pour analyser les échanges lors de la requête de connexion depuis votre voisi.

**Question 8: Quelle est votre règle ? Montrer la règle et expliquer comment elle fonctionne. Montre le message d'alerte enregistré dans le fichier d'alertes.**

---

**Reponse :**  
```bash
alert tcp 192.168.0.0/24 any -> 192.168.0.164 any (msg:"SSH connection";content"SSH-2.0";nocase;sid:40000006;rev:1;)
```

On contrôle toutes communications depuis le même sous-réseau vers le host qui a comme adresse IP 192.168.0.164 et on vérifie si l'en-tête d'un packet sniffé contient le mot clé `SSH-2.0` sans casse.

![image](images/SSH_Detection.PNG)

---

--

### Analyse de logs

Lancer Wireshark et faire une capture du trafic sur l'interface connectée au bridge. Générez du trafic avec votre machine hôte qui corresponde à l'une des règles que vous avez ajouté à votre fichier de configuration personnel. Arrêtez la capture et enregistrez-la dans un fichier.

**Question 9: Quelle est l'option de Snort qui permet d'analyser un fichier pcap ou un fichier log ?**

---

**Reponse :**   
```bash
snort -r fichier.pcap
```

---

Utiliser l'option correcte de Snort pour analyser le fichier de capture Wireshark.

**Question 10: Quelle est le comportement de Snort avec un fichier de capture ? Y-a-t'il une difference par rapport à l'analyse en temps réel ? Est-ce que des alertes sont aussi enregistrées dans le fichier d'alertes?**

---

**Reponse :**   
Il n'y a aucune différence par rapport à l'analyse en temps réel. Il traite le fichier comme s'il recevait les infos depuis la carte réseau. Cela veut dire qu'il enregistre aussi les alertes dans le fichier d'alerte.

---

<sub>This guide draws heavily on http://cs.mvnu.edu/twiki/bin/view/Main/CisLab82014</sub>
