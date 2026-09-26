---
title: Analyza batch1 malwaru ESET
description: Prvni analyza z treninkoveho setu ESET pro hired Analysty
date: 2026-09-26 11:34:00 +0800
categories: [Malware]
tags: [stealer]
pin: false
---


čas strávený: cca 6-8 hodin čistého času

Family Aliasy: 
[graftor](https://www.virustotal.com/gui/search?query=engines%3Agraftor)
[dybalom](https://www.virustotal.com/gui/search?query=engines%3Adybalom)
[fignoto](https://www.virustotal.com/gui/search?query=engines%3Afignoto)

AI využití:
z 90% pro matematické operace nebo psaní skriptů, prostě dirty work, známe XOR decrypt funkci, decryptni to, ať to tam nemusím vkládat sám.
10% z toho pomoc při analýze neznámých funkcí nebo šifrování (př. fn_SearchForString, LCG generátor, IE <-> cache atd.)

------------------------------------

# Pokus o hloubkový popis

Malware bych zařadil do kategorie Stealer. Virustotal psal Downloader, což je možné, když tam byl pokus o Shell open, problém je, že resource to už neobsahoval a obsahoval pouze C2 server

Funkcionalita:

Krádež přihlašovacích údajů z
MSN, AIM, Yahoo, Paltalk, Steam, NO IP DUC, DynDNS, Firefox, IE, Filezilla, FlashFXP
Následně sám sebe smaže, což mělo být asi pojištěno tím Shell command "open" na začátku


# Moje výpisky, které jsem si psal.
#### Inicializace

Program si pomocí funkce (fn_decrypt) dešifruje stringy pro adresáře, jak na disku, tak pro registry (názvy v obrázku)

![](/assets/img/Pasted%20image%2020260925164227.png)
Následně vytáhneme Resource pomocí FindResourceA s jménem "#1", ve kterém se nachází přepínače (rádoby config) a zašifrovaný C2 server "http warezbb:info/Dont_Bother/index.php"

Prvně ale procházíme kontrolou pár přepínačů, funkcí a čteme z registrů PATHs ke složkám jako appdata, localappdata atd.

##### Program dál kontroluje `if ( ResourceBytes[0x73] )` a při úspěchu by vytvořil nový soubor v %temp% a dal ShellExecuteA. Problém je, že ten resource není


#### Inicializace a resolve funkcí -> sub_40464D

Program v této funkci decryptne stringy, které jsou vlastně knihovny a funkce -> pro příklad advapi32.dll, CryptCreateHash nebo CredFree)

![](/assets/img/Pasted%20image%2020260925175517.png)


#### Získání credentials ze starých .NET passport service a MS Live a poslání na server - sub_401A96 a sub_4042B0

Zde jsem získal dešifrováním 2 stringy, které jsem si našel a patří k službám napsaným v nadpise a u kterých vidím, že se Enumerují přes CredEnumerate.
`Passport.Net\*`
`WindowsLive:name=*`

První (Passport) je šifrovaný, takže se odšifrovává skrz CryptUnprotectData s využitím CRYPTOAPI_BLOBU, o kterém jsem se poradil s AI z důvodu toho, že jsem moc nechápal to random uspořádání bytes, ale dostal jsem odpověď, že je to GUID, které bylo hardcoded od Microsoftu v tomto šifrování, po odšifrování posíláme do funkce sub_4042B0

Druhý už ne, ten se jen vypíše a pošle do funkce sub_4042B0

Funkce sub_4042B0, vezme argumenty ('0´, 0x0000, Jmeno, Heslo), sestaví URL a pošle request na server, který si to následně nejspíše uloží

#### Získání credentials z Google talk a poslání na server - sub_401CE5

Program dešifruje cestu k registrům Software\Google\Google Talk\Accounts
a template pro výpis, následně si Enumeratne ty účty a prochází je

Vytvoří si buffer spojením UserName a ComputerName

Nicméně, zde jsem opět narazil na nějaké neznámo, takže přišla rada s internetem a AI, které mi řeklo, že Google Talk používá šifrování "založené na LCG generátoru (Linear Congruential Generator) a dynamické entropii odvozené z identity systému." spolu s **Google Talk Hardcoded Master Salt / Magic Vector**, který je inicializovaný do v16[0-3] a využívá se právě s tím Bufferem

Následně se toto ještě musí deobfuskovat, jelikož "Google Talk ukládal binární blob zakódovaný po hex-nibblech s posunem ASCII"

Pak přichází už jen opět CryptUnprotectData s daty a BLOBEM s entropií ze zmíněného LCG generátoru, finálně se data opět pošlou na C2 server, tentokrát s prvním argumentem "31 00 00 00" místo "00 00 00 00"

#### Získáni credentials z MSM, AIM, Yahoo Messengeru a poslání na server - sub_401FA0

Program využívá jako argument string získaný z registrů pro ProgramFiles
Prohledává "ProgramFiles\Trillian\users\default\" a v něm ty .ini soubory

Načte všechny 3 .ini pomocí funkce do bufferu, v tom přes vyhledávání hledá pozice, kde se nachází "name=" a "password=", ty samozřejmě zpracuje a vezme si jen to potřebné. Hesla jsou opět šifrovaná, tentokrát jednoduším XOREM, jehož klíče jsou uložené na začátku funkce.
Pošle všechny 3 výsledky na server

![](/assets/img/Pasted%20image%2020260925234100.png)


#### Získaní credentials z Pidgin clientu a poslání na server - sub_4023F5

Tady je funkcionalita stejná jako u MSM, AIM, Yahoo
Dešifrují se stringy pro xml hledání, včetně "\.purple\accounts.xml", ve kterých jsou data uložena a poté se projíždí accounts.xml, hledají se xml tagy pro name a password a následně se pošlou

![](/assets/img/Pasted%20image%2020260925235111.png)


#### Získání credentials z Paltalk klientu a poslání na server - sub_4025D0

Program si dešifruje /Software/Paltalk a v registrech z toho čte údaje

Jméno normálně, heslo je zde upraveno, že "každý znak původního hesla je zakódován do 4 ASCII číslic", takže se využívá algoritmus, který to vrátí zpět do znaku a využívá k tomu i klíč vytvořený z VolumeSerialNumber a Bufferu pro Nickname (rotováno doprava o pozici).

`// v6 ukazuje na začátek 4místného bloku v11`
`// v8 = v6 / 4 (index znaku ve výsledném heslu v15)`
`// v11[v6] až v11[v6+3] jsou 4 ASCII číslice`

`v9 = 10 * (v11[v6 + 1] - '0' + 10 * (v11[v6] - '0')) - v16[v8];`
`v15[v8] = (v11[v6 + 2] - '0') + v9 - v8 - 122; // v7[1] odpovídá v11[v6 + 2]`

#### Získání credentials ze Steam client registru a poslání na server - sub_402970

Program si prvně dešifruje stringy pro registr a název dll.

získá si z registru Path kde je steam a skrz LoadLibraryA si načte Steam.dll, ve kterém se nachází funkce **SteamDecryptdataForThisMachine**

Poté opět skrz fn_ReadFileMemory prohledává strukturu ClientRegistry.blob, což je stromová struktura, nicméně se to prohledává skrz pevné délky (41 u "Users" a 40 u "Phrase")

![](/assets/img/Pasted%20image%2020260926161733.png)

Po nalezení se zašifrované heslo prožene funkcí, ke které si program získá adresu skrz GetProcAddress a následně se pošle na server

![](/assets/img/Pasted%20image%2020260926161907.png)


#### Získání credentials z NO-IP Dynamic update client a poslání na server - sub_402C5E

Jednoduší funkce, program si decryptne opet cestu k registru, jmena ktera v nem hledat, heslo nasledne projede jednoduchym base64 decodem a pošle na server

![](/assets/img/Pasted%20image%2020260926162521.png)

#### Získání credentials z DynDNS a poslání na server - sub_402D3A

Program bere jako argument CommonAppData path. Dekryptuje si statický klíč pro XOR dešifrování a path ke config.dyndns. Z něj pak čte Username i Password. Heslo dešifruje skrz ten XOR decrypt se statickým klíčem "t6KzXhCh".

Zmátlo mě využití v22, které je jen ""~]iAk", ale pak jsem si vzpomněl, že už jsem to řešil s AI když jsem to viděl poprvé a má to být pouze HexRays optimalizace pole znaků.

![](/assets/img/Pasted%20image%2020260926164013.png)

#### Získání credentials z Firefoxu a poslání na server - sub_402F6A

*První větší funkce a první funkce, u které se v tomto malwaru vyplácí to, že si beru Vaše rady, že má analýzu vést analytik a ne AI, protože jsem ho nachytal na tom, že u špinavé práce s dešifrovním blouznil a málem to skončilo u toho, že mi u proměnných pro LoadLibrary dával signons.txt soubory atd.* 

Program si prvně dešifruje cestu k registru, dll soubory pro Load, funkce z těchto DLL, profile PATHs a signons

Loadne si libs, načte adresy funkcí a pak hledá v profiles.ini řádky s Path=, ve kterých je reálný název, který musí hledat jakožto složku. Poté whilem projede oba signons.

Jméno i heslo nejprve Base64Decodne a poté dešifruje skrz PK11SDR_Decrypt, který mu vrátí struct SECItem, který já nemám v IDE, takže mě to prvně zmátlo, že tam mám `strncpy(var_decrypted_password, Source, Count);`
Nicméně nahoře při inicializaci to odpovídá tomu structu
Pak se pošle na server web url, jméno i heslo
Opakuje se to pro záznamy v obou signons

![](/assets/img/Pasted%20image%2020260926173733.png)

![](/assets/img/Pasted%20image%2020260926173805.png)


#### Ziskání credentials z IE a poslání na server - sub_403B1E

*Zde byl AI assist při struktech a vysvětlení spojitosti mezi cache a IE registry*

Program si prvně dešifruje cestu k registru. 
Problém je, že IE v registrech ukládá hesla, ale ne jejich URL, k tomu tam byly hashe, takže si program i zvolí, že si weby ve kterých by mohla být hesla uložená vyčte z cache history, jelikož když to tam bude uložené, musel to navštívit.

Projedeme ten cache, ke každé stránce se vytvoří hash funkcí sub_404579, pokusí se najít ten hash v registrech a pokud je, tak se začne dešifrovat heslo, to se dělá skrz CryptUnprotectData s určitou entropií, kterou IE využíval. UnprotectData vrací BLOB, takže si z toho vypočtou offsety a pošle se na server.

![](/assets/img/Pasted%20image%2020260926190816.png)

#### Získání credentials z Filezilla a poslání na server - sub_403D9B

Program v si jen dešifruje xml tagy pro host, jméno a heslo spolu s cestou k recentserver.xml a v tom souboru přes ReadFileToMemory ukládá tyto values a následně je pošle na server, žádné šifrování hesla

![](/assets/img/Pasted%20image%2020260926175135.png)


#### Získání credentials z FlashFXP a poslání na server - sub_40400C

Program si dešifruje statický klíč používaný FlashFXP pro šifrování, path k Sites.dat a potřebné hledací stringy ip=, user=, pass=.
Má vlastní funkci na hledání, do které prostě pošle na hledání ten "ip=" a funkce mu vrátí právě tu hodnotu.

Pouze u hesla se provede HexString na bajty a pak šifrování s tím statickým klíčem "yA36zA48dEhfrvghGRg57h5UlDv3"

![](/assets/img/Pasted%20image%2020260926180454.png)

#### Úklid

Program se v posledních funkcích vlastně jen zbaví loaded libraries a sám se vymaže po pár sekundách, aby se stihl ukončit program.

#### SendCredentialsToC2 (sub_4042B0)
Seznam argumentů "a=?" a co znamenají

2 = MSN ini
3 = AIM ini 
4 = Yahoo ini
6 = Paltalk
7 = steam blob
8 = NO IP DUC
9 = DynDNS
10 = firefox
11 = InternetExplorer
12 = Filezilla
13 = FlashFXP
