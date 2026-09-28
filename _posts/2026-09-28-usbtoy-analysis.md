---
title: Analyza USBToy malwaru ESET
description: Druha analyza z treninkoveho setu ESET pro hired Analysty
date: 2026-09-28 11:34:00 +0800
categories: [Malware]
tags: [worm]
pin: false
---

### Analýza

Family labels: USBToy, BusToy

**Program je worm.**

**Při startu se kopíruje do startup/systemnt.exe a system32/mslogon.exe, s tím, že, pokud se vše podaří, se spustí jako mslogon.exe**

**Pokud se však worm spustí  skrz startup, zobrazí se Bible scripture, asi jako provokace (já sám neviděl ten Window, nechci riskovat, funkcionalitu jsem zanalyzoval).**

**Takže je jedno jestli se spustí jako Troy.exe, mslogon.exe nebo Systemnt.exe, ve všech případech se nakopírují a spustí se v pozadí jako Mslogon a pak už jen tiše vyčkává na event připojení nového Drivu(537).**
**Mezitím se kontroluje přítomnost wincfgs.exe.**



### První Kód se ukrývá v _cinit a initterm

![](/assets/img/Pasted%20image%2020260928164415.png)

`Malware_Struct`
`0-4 this ptr`
`4 - 264 = startup/systemnt.exe`
`264- 524 Cesta ke spuštěnému wormu na disku`


Inicializuje se Malware_Struct hodnotami co jsou nahoře a spustí se infekce.
Program poté dle toho, v jakém stavu je (Už běží jako mslogon, atd.), spustí Timer, který zobrazí jakési Bible scriptures (+ obsahuje easter egg -> "Can you find programs interface?).

Poté jen nastaví startup folder aby nebyla vidět a READONLY a zkontroluje, zda jede wincfgs.exe a jestli ano, tak ho zastaví (nějaká ochrana proti odhalení nejspíš)

##### Infekce

![](/assets/img/Pasted%20image%2020260928160411.png)

Kontrola, zda current dir je REMOVABLE. V tom případě se v fn_Setup_USB_Autorun vytvoří Autorun.inf s ![](/assets/img/Pasted%20image%2020260928160550.png), takže se náš Worm spustí při každém připojení drivu. Poté se zavolá explorer.exe, aby zobrazil nově připojenou flashku (imitace normálního chování)

Poté kopírujeme náš Troy.exe do (this + 4), což je startup/systemnt.exe a system32/mslogon.exe a Executne se už v podobě mslogon, aby vypadal důveryhodně.

return
1 = this + 264 = spuštěno jako mslogon
2 = this + 264 = spustěno jako systemnt
3 = this + 264 = spustšěno jako systemnt & fail zkopírovat se do mslogon
### WinMain

Prvotně nastavení jen Okna, Acceleratorů, stringů a Icon, ale v v2.lpfnWndProc = sub_401C6 najdem
`if ( Msg == 537 )`
  `{`
    `fn_Malware_Begins(Malware_Struct, wParam, lParam);`
    `return 0;`
  `}`
Což je WM_DEVICECHANGE, tedy... 
Poté co  worm sám sebe nakopíroval teď tiše čeká na event, kdy se připojí další disk. 
Tam se opět dostane do toho drivu, vytvoří Autorun.inf a nakopíruje náš aktuálně spuštěný worm (this + 264) do Drive:/Troy.exe a schová ho

![](/assets/img/Pasted%20image%2020260928162551.png)
