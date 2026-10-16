# Gestione attività Linux

App desktop Python + Qt che riprende disposizione, grafici e colori delle schede **Processi** e **Prestazioni** di Gestione attività di Windows 11. Prima versione sviluppata e verificata su CachyOS con GNOME/Wayland, con dati reali di questo computer.

## Avvio

```bash
git clone https://github.com/GiacomoCunardi2005/linux-task-manager.git
cd linux-task-manager
./start.sh
```

Il primo avvio crea un ambiente Python locale e installa Qt Essentials e psutil, se mancanti. Non richiede root. Su altre distribuzioni servono Python 3 con venv/pip e le librerie di sistema per Qt/Wayland o X11. Su Arch/CachyOS i prerequisiti sono `python`, `python-pip` e le normali librerie del desktop. L’avvio desktop locale non crea servizi né apre porte di rete. La modalità server è separata e opzionale.

Per aggiungerla al menu applicazioni dell'utente:

```bash
./install-desktop.sh
```

## Server senza schermo e monitoraggio da un altro PC

Sul computer da monitorare servono **Python 3, venv/pip, OpenSSL e Git**. Non occorrono desktop, Qt, X11 o Wayland. L’installatore usa soltanto psutil come dipendenza Python. Su Debian/Ubuntu i pacchetti sono `python3-venv python3-pip openssl git`; su Arch/CachyOS `python python-pip openssl git`.

Da terminale o SSH, come utente normale:

```bash
git clone https://github.com/GiacomoCunardi2005/linux-task-manager.git
cd linux-task-manager
./install-server.sh
```

L’installatore copia il server in `~/.local/share/linux-task-manager-server`, crea un ambiente `.venv-server` separato e un servizio systemd dell’utente. Stampa una **chiave di accesso**: copiala e conservala privata. Chiave e certificato restano in `~/.config/linux-task-manager-server` con token e chiave privata leggibili solo dall’utente. Reinstallare aggiorna il codice mantenendo la stessa chiave.

Per tenerlo attivo anche dopo logout e avviarlo al riavvio senza login, esegui una volta sul server:

```bash
sudo loginctl enable-linger "$USER"
```

Sul PC con l’interfaccia grafica, avvia/aggiorna l’app e premi **Connetti a un server** nella barra superiore. Inserisci **IP o nome host**, porta **8765** e chiave completa. Processi e Prestazioni mostreranno i dati remoti, compresi dispositivi e cronologie. La barra indica sempre il PC remoto; dallo stesso pulsante scegli **Torna al PC locale**. La chiave non viene salvata dal client: si reinserisce a ogni connessione/avvio.

Il servizio ascolta su tutte le IPv4, TCP 8765. Se il server ha un firewall, consenti questa porta soltanto al PC di monitoraggio o alla rete privata/VPN. Usa questa versione su LAN o VPN; non è progettata come servizio pubblico Internet. HTTPS è obbligatorio: la chiave contiene l’impronta SHA-256 del certificato e il token, e il client verifica l’impronta **prima** di inviare il token. Non accetta un certificato diverso, neppure se firmato da un’autorità pubblica. Il certificato generato dura dieci anni; per rinnovarlo fermare il servizio, eliminare solo `certificate.pem` e `private-key.pem`, rieseguire `--init` e usare la nuova chiave completa nei client.

Il monitoraggio remoto è **in sola lettura**: non esistono comandi di terminazione remoti e il client non può applicare i PID remoti al PC locale. I dati includono nomi dei processi, utenti, eseguibili, montaggi e indirizzi di rete; gli argomenti completi dei comandi non vengono trasmessi. Un identificatore HMAC per sessione distingue gli script senza esporne gli argomenti. Sono visibili solo i contatori accessibili all’utente che esegue il server; NetHogs e `iw` restano opzionali e richiedono i rispettivi permessi. Alla perdita della connessione compare un errore e l’app ritenta automaticamente; gli ultimi valori visualizzati non sono dati live finché il collegamento non riprende. La cronologia desktop comincia al collegamento, non viene archiviata sul server.

Comandi utili sul server:

```bash
systemctl --user status linux-task-manager-server
journalctl --user -u linux-task-manager-server -n 30
~/.local/share/linux-task-manager-server/start-server.sh --show-key
systemctl --user stop linux-task-manager-server
```

Su distribuzioni senza systemd, oppure per l’avvio manuale dalla cartella del progetto:

```bash
./start-server.sh --init
./start-server.sh --host 0.0.0.0 --port 8765
```

`--host` limita l’ascolto a un IP; per IPv6 usa ad esempio `--host ::` nell’avvio manuale. `--config /percorso` cambia la directory delle credenziali. Per personalizzare l’indirizzo/porta del servizio usa `systemctl --user edit linux-task-manager-server`, sostituendo `ExecStart` con il percorso assoluto del launcher e i nuovi argomenti; poi riavvia il servizio. `Ctrl+C` o SIGTERM arrestano il campionatore e il relativo helper NetHogs.

Per disinstallare il servizio:

```bash
systemctl --user disable --now linux-task-manager-server
rm ~/.config/systemd/user/linux-task-manager-server.service
systemctl --user daemon-reload
```

Poi puoi rimuovere `~/.local/share/linux-task-manager-server` e, se non servono più, le credenziali in `~/.config/linux-task-manager-server`. L’eventuale linger è una proprietà condivisa dagli altri servizi dell’utente: non viene disabilitato automaticamente.

## Cosa funziona

- Processi: applicazioni raggruppate con PID espandibili, ricerca per nome/PID/utente, ordinamento numerico, CPU, memoria RSS, I/O disco, traffico TCP/UDP e stato; terminazione del singolo processo del proprio utente con conferma e controllo dell’identità PID + data di avvio.
- CPU totale e per processore logico, frequenza, processi, thread, file allocati dal kernel, uptime, topologia e cache.
- RAM: velocità configurata in MT/s, slot utilizzati, tipo DDR, formato e capacità dei moduli, memoria installata e utilizzabile, impegno/limite Linux, slab recuperabile e non recuperabile, cache, buffer, memoria condivisa e swap; grafico e composizione della memoria.
- Dischi: rilevamento automatico di inserimento/rimozione, tempo di attività, letture/scritture, latenza media, capacità, modello, montaggi e bus. USB: velocità negoziata, versione dichiarata e prodotto; NVMe/PCIe: velocità e larghezza del collegamento.
- Rete: invio/ricezione effettivi, scala automatica, indirizzi IPv4/IPv6/MAC, MTU, driver, velocità e duplex Ethernet. Wi-Fi: SSID, BSSID, standard 4/5/6/6E/7 quando riconoscibile, banda, frequenza, canale, larghezza, segnale e bitrate radio RX/TX (richiede il comando opzionale `iw`). Le velocità negoziate non rappresentano la velocità Internet.
- NPU: acceleratori Linux `/sys/class/accel`, utilizzo Intel dal tempo dei job, memoria residente, frequenza e stato energetico dove esposti dal driver.
- GPU DRM: motori accessibili tramite fdinfo, utilizzo sysfs quando presente, VRAM e frequenza se esposte dal driver.
- Cronologia reale di 60 secondi, campionamento ogni secondo, pausa della visualizzazione, copia informazioni e navigazione comprimibile. Trascina la barra del titolo per spostare; doppio clic per ingrandire; angolo inferiore destro per ridimensionare.

La cronologia si riempie dopo l'avvio: non contiene campioni simulati. La pausa congela la visualizzazione; il campionamento continua e al ripristino viene mostrata la cronologia aggiornata. Il menu `…` attiva i grafici per processore logico.

## Limiti di questa prima versione

Il menu richiudibile contiene solo Processi e Prestazioni. La terminazione invia SIGTERM al singolo processo selezionato: non forza la chiusura né termina automaticamente i discendenti. Può causare la perdita dei dati non salvati. I processi altrui, PID 1 e l’app stessa sono protetti.

Le voci raggruppano processi dello stesso utente con lo stesso nome di eseguibile; gli helper con prefisso dell’app si uniscono soltanto quando il loro vero padre appartiene a quell’app. Gli interpreti con argomenti diversi rimangono separati. È un raggruppamento operativo Linux, non l’identità delle app Windows: programmi diversi con lo stesso nome di eseguibile possono condividere una voce, sempre espandibile. CPU, RSS, disco e rete vengono sommati sui dati disponibili; RSS può contare più volte pagine condivise. I gruppi non sono terminabili in blocco: espanderli e selezionare il PID desiderato.

La rete per processo usa il comando opzionale [NetHogs](https://github.com/raboof/nethogs), già funzionante con i permessi di cattura su questo computer. Un sottoprocesso legge contatori TCP e UDP; l’app grafica rimane senza privilegi e non configura capabilities né esegue sudo. Il collector si arresta alla chiusura e si riavvia se cambiano le interfacce. Mancanza del programma, permessi insufficienti, contatori iniziali o scaduti producono N/D. I contatori sono associati a PID + data di creazione: PID riutilizzati non ereditano il traffico. Connessioni/pacchetti non attribuiti da NetHogs possono mancare; il totale delle interfacce in testata non deve coincidere con la somma delle righe. I nuovi processi hanno CPU e I/O N/D fino al secondo campione.

Su Intel, fdinfo comprende soltanto i client leggibili dall'utente e può sottostimare l'utilizzo totale della GPU; un dato mancante è indicato come non disponibile. Le GPU sono identificate per produttore. AMD e NVIDIA e le altre distribuzioni non sono state provate su hardware reale. Le metriche specifiche di Windows non hanno sempre un equivalente Linux: i file allocati del kernel sostituiscono gli handle; la virtualizzazione indica il supporto CPU. Capacità espresse in potenze di 1024, come nel riferimento Windows. Dischi, interfacce di rete, GPU e NPU vengono rilevati a ogni campione: non occorre riaprire l’app. Le cronologie vengono eliminate quando un dispositivo è rimosso o sostituito; il primo campione di un nuovo disco o NPU non inventa un utilizzo pari a zero.

La somiglianza visiva è una ricostruzione, non una corrispondenza pixel per pixel: i font disponibili e alcuni dati Linux differiscono. Se Segoe UI non è installato viene usato Noto Sans. Nessun font o asset Microsoft viene redistribuito. Il riferimento visivo di Prestazioni è la [guida TechRadar](https://www.techradar.com/how-to/how-to-use-the-redesigned-task-manager-in-windows-11s-2022-update).

## Verifica

```bash
.venv/bin/python -m unittest -v test_metrics test_ui test_processes test_hardware test_process_network test_server
```

Test della contabilizzazione CPU, reset dei contatori, coerenza dei dati Linux e interazione delle viste Qt (risorse, pausa, processori logici, copia, finestra compatta). La cartella locale `reference/` non viene pubblicata: può contenere schermate con dati del computer e riferimenti esterni. I test UI producono schermate reali in `reference/linux-*.png` usando Qt offscreen.

Per rimuovere il collegamento dal menu, eliminare `~/.local/share/applications/linux-task-manager.desktop`. Il progetto e le dipendenze restano interamente in questa cartella.

La pagina Processi è verificata anche con ricerca letterale, ordinamento numerico, selezione stabile, pausa e annullamento/conferma della terminazione; il test dei segnali termina solo un sottoprocesso di prova. Le icone dei processi provengono dai file `.desktop` e dal tema di icone installato. Per fissare l’app alla barra, installare il collegamento e scegliere «Aggiungi ai preferiti» dal menu dell’icona.

Fonte visiva aggiuntiva: [schermata Windows 11 di Lonely Mobiler](https://loumo.jp/archives/28065).

I dettagli hardware della RAM si leggono una sola volta dalla cache udev (`udevadm info` sul dispositivo DMI), senza sudo. Su sistemi senza udev o con firmware incompleto restano «Non disponibile». La velocità configurata non viene sostituita dalla velocità massima nominale. «Riservata al sistema» è la differenza tra RAM installata secondo il firmware e MemTotal Linux, non una misura separata della sola riserva hardware. I valori Impegnata/limite e slab sono contatori Linux, diversi dai pool di Windows.

La velocità USB proviene dal collegamento attuale in sysfs, non dalla velocità massima stampata sul dispositivo; il tipo resta «Disco USB» perché alcuni adattatori/chiavette dichiarano erroneamente il flag di rotazione. L’app non monta, formatta né scrive sui dispositivi. I dettagli NPU attualmente supportano i contatori sysfs Intel; le altre NPU riconosciute restano visibili con i dati disponibili. Se mancano `iw`, permessi o contatori del driver, i campi interessati restano non disponibili. I dettagli Wi-Fi possono contenere SSID, BSSID e indirizzi locali: le schermate di test in `reference/` rimangono escluse da Git.
