# Gestione attività Linux

App desktop Python + Qt che riprende disposizione, grafici e colori delle schede **Processi** e **Prestazioni** di Gestione attività di Windows 11. Prima versione sviluppata e verificata su CachyOS con GNOME/Wayland, con dati reali di questo computer.

## Avvio

```bash
git clone https://github.com/GiacomoCunardi2005/linux-task-manager.git
cd linux-task-manager
./start.sh
```

Il primo avvio crea un ambiente Python locale e installa Qt Essentials e psutil, se mancanti. Non richiede root. Su altre distribuzioni servono Python 3 con venv/pip e le librerie di sistema per Qt/Wayland o X11. Su Arch/CachyOS i prerequisiti sono `python`, `python-pip` e le normali librerie del desktop. Nessun servizio, porta di rete o modifica alla configurazione del sistema.

Per aggiungerla al menu applicazioni dell'utente:

```bash
./install-desktop.sh
```

## Cosa funziona

- Processi: tabella in tempo reale, ricerca per nome/PID/utente, ordinamento numerico, CPU, memoria RSS, I/O disco e stato; terminazione del singolo processo del proprio utente con conferma e controllo dell’identità PID + data di avvio.
- CPU totale e per processore logico, frequenza, processi, thread, file allocati dal kernel, uptime, topologia e cache.
- RAM: velocità configurata in MT/s, slot utilizzati, tipo DDR, formato e capacità dei moduli, memoria installata e utilizzabile, impegno/limite Linux, slab recuperabile e non recuperabile, cache, buffer, memoria condivisa e swap; grafico e composizione della memoria.
- Dischi: tempo di attività, letture/scritture, latenza media delle operazioni completate, capacità e modello.
- Rete: invio/ricezione per interfaccia, scala automatica e indirizzi IPv4/IPv6.
- GPU DRM: motori accessibili tramite fdinfo, utilizzo sysfs quando presente, VRAM e frequenza se esposte dal driver.
- Cronologia reale di 60 secondi, campionamento ogni secondo, pausa della visualizzazione, copia informazioni e navigazione comprimibile. Trascina la barra del titolo per spostare; doppio clic per ingrandire; angolo inferiore destro per ridimensionare.

La cronologia si riempie dopo l'avvio: non contiene campioni simulati. La pausa congela la visualizzazione; il campionamento continua e al ripristino viene mostrata la cronologia aggiornata. Il menu `…` attiva i grafici per processore logico.

## Limiti di questa prima versione

Il menu richiudibile contiene solo Processi e Prestazioni. La terminazione invia SIGTERM al singolo processo selezionato: non forza la chiusura né termina automaticamente i discendenti. Può causare la perdita dei dati non salvati. I processi altrui, PID 1 e l’app stessa sono protetti.

Le righe sono singoli processi Linux, senza raggruppamenti fittizi delle applicazioni. CPU normalizzata sul totale dei processori logici, come Windows; memoria RSS (può comprendere pagine condivise), disco letture + scritture fisiche. La velocità di rete per processo non è disponibile nel backend e appare N/D; il totale in testata è quello delle interfacce di sistema. I nuovi processi hanno CPU e I/O N/D fino al secondo campione.

Su Intel, fdinfo comprende soltanto i client leggibili dall'utente e può sottostimare l'utilizzo totale della GPU; un dato mancante è indicato come non disponibile. Le GPU sono identificate per produttore. AMD e NVIDIA e le altre distribuzioni non sono state provate su hardware reale. Le metriche specifiche di Windows non hanno sempre un equivalente Linux: i file allocati del kernel sostituiscono gli handle; la virtualizzazione indica il supporto CPU. Capacità espresse in potenze di 1024, come nel riferimento Windows. I dispositivi sono rilevati all'avvio: riaprire l'app dopo collegamenti o rimozioni.

La somiglianza visiva è una ricostruzione, non una corrispondenza pixel per pixel: i font disponibili e alcuni dati Linux differiscono. Se Segoe UI non è installato viene usato Noto Sans. Nessun font o asset Microsoft viene redistribuito. Il riferimento visivo di Prestazioni è la [guida TechRadar](https://www.techradar.com/how-to/how-to-use-the-redesigned-task-manager-in-windows-11s-2022-update).

## Verifica

```bash
.venv/bin/python -m unittest -v test_metrics test_ui test_processes
```

Test della contabilizzazione CPU, reset dei contatori, coerenza dei dati Linux e interazione delle viste Qt (risorse, pausa, processori logici, copia, finestra compatta). La cartella locale `reference/` non viene pubblicata: può contenere schermate con dati del computer e riferimenti esterni. I test UI producono schermate reali in `reference/linux-*.png` usando Qt offscreen.

Per rimuovere il collegamento dal menu, eliminare `~/.local/share/applications/linux-task-manager.desktop`. Il progetto e le dipendenze restano interamente in questa cartella.

La pagina Processi è verificata anche con ricerca letterale, ordinamento numerico, selezione stabile, pausa e annullamento/conferma della terminazione; il test dei segnali termina solo un sottoprocesso di prova. Le icone dei processi provengono dai file `.desktop` e dal tema di icone installato. Per fissare l’app alla barra, installare il collegamento e scegliere «Aggiungi ai preferiti» dal menu dell’icona.

Fonte visiva aggiuntiva: [schermata Windows 11 di Lonely Mobiler](https://loumo.jp/archives/28065).

I dettagli hardware della RAM si leggono una sola volta dalla cache udev (`udevadm info` sul dispositivo DMI), senza sudo. Su sistemi senza udev o con firmware incompleto restano «Non disponibile». La velocità configurata non viene sostituita dalla velocità massima nominale. «Riservata al sistema» è la differenza tra RAM installata secondo il firmware e MemTotal Linux, non una misura separata della sola riserva hardware. I valori Impegnata/limite e slab sono contatori Linux, diversi dai pool di Windows.
