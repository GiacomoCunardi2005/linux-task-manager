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

- Processi: applicazioni raggruppate con PID espandibili, ricerca per nome/PID/utente, ordinamento numerico, CPU, memoria RSS, I/O disco, traffico TCP/UDP e stato; terminazione del singolo processo o di tutto il gruppo, solo del proprio utente, con conferma e controllo dell’identità PID + data di avvio; segnalazione euristica dei comportamenti sospetti.
- CPU totale e per processore logico, frequenza, processi, thread, file allocati dal kernel, uptime, topologia e cache.
- RAM: velocità configurata in MT/s, slot utilizzati, tipo DDR, formato e capacità dei moduli, memoria installata e utilizzabile, impegno/limite Linux, slab recuperabile e non recuperabile, cache, buffer, memoria condivisa e swap; grafico e composizione della memoria.
- Dischi: rilevamento automatico di inserimento/rimozione, tempo di attività, letture/scritture, latenza media, capacità, modello, montaggi e bus. USB: velocità negoziata, versione dichiarata e prodotto; NVMe/PCIe: velocità e larghezza del collegamento.
- Rete: produttore e modello della scheda da udev/sysfs, ID hardware, fornitore dell’ID se diverso dal produttore dichiarato, interfaccia Linux, bus e posizione; invio/ricezione effettivi, scala automatica, indirizzi IPv4/IPv6/MAC, MTU, driver, velocità e duplex Ethernet. Wi-Fi: SSID, BSSID, standard 4/5/6/6E/7 quando riconoscibile, banda, frequenza, canale, larghezza, segnale e bitrate radio RX/TX (richiede il comando opzionale `iw`). Le velocità negoziate non rappresentano la velocità Internet.
- Collegamenti: albero USB con root hub, hub intermedi e dispositivi, velocità negoziata per ciascun segmento, controller, porte e ID USB. Router USB4 e Thunderbolt separati, generazione del kernel, autorizzazione e velocità RX/TX calcolate dalle corsie, quando disponibili. Funziona anche da remoto con un server aggiornato.
- NPU: acceleratori Linux `/sys/class/accel`, utilizzo Intel dal tempo dei job, memoria residente, frequenza e stato energetico dove esposti dal driver.
- GPU DRM: motori accessibili tramite fdinfo, utilizzo sysfs quando presente, VRAM e frequenza se esposte dal driver.
- Cronologia reale di 60 secondi, campionamento ogni secondo, pausa della visualizzazione, copia informazioni e navigazione comprimibile. Trascina la barra del titolo per spostare; doppio clic per ingrandire; angolo inferiore destro per ridimensionare.

La cronologia si riempie dopo l'avvio: non contiene campioni simulati. La pausa congela la visualizzazione; il campionamento continua e al ripristino viene mostrata la cronologia aggiornata. Il menu `…` attiva i grafici per processore logico.

## Limiti di questa prima versione

Il menu richiudibile contiene solo Processi e Prestazioni. La terminazione invia SIGTERM al processo selezionato oppure, se è selezionato un gruppo, a ciascun suo PID dopo una sola conferma che li elenca; ogni PID è ricontrollato con la data di avvio. Non forza la chiusura né termina automaticamente i discendenti. Può causare la perdita dei dati non salvati. I processi altrui, PID 1 e l’app stessa sono protetti.

Le voci raggruppano processi dello stesso utente con lo stesso nome di eseguibile; gli helper con prefisso dell’app si uniscono soltanto quando il loro vero padre appartiene a quell’app. Gli interpreti con argomenti diversi rimangono separati. È un raggruppamento operativo Linux, non l’identità delle app Windows: programmi diversi con lo stesso nome di eseguibile possono condividere una voce, sempre espandibile. CPU, RSS, disco e rete vengono sommati sui dati disponibili; RSS può contare più volte pagine condivise. Selezionando la voce del gruppo, «Termina attività» chiude tutti i suoi processi; per chiuderne uno solo espandere il gruppo e selezionare il PID.

La rete per processo usa il comando opzionale [NetHogs](https://github.com/raboof/nethogs), già funzionante con i permessi di cattura su questo computer. Un sottoprocesso legge contatori TCP e UDP; l’app grafica rimane senza privilegi e non configura capabilities né esegue sudo. Il collector si arresta alla chiusura e si riavvia se cambiano le interfacce. Mancanza del programma, permessi insufficienti, contatori iniziali o scaduti producono N/D. I contatori sono associati a PID + data di creazione: PID riutilizzati non ereditano il traffico. Connessioni/pacchetti non attribuiti da NetHogs possono mancare; il totale delle interfacce in testata non deve coincidere con la somma delle righe. I nuovi processi hanno CPU e I/O N/D fino al secondo campione.

Su Intel, fdinfo comprende soltanto i client leggibili dall'utente e può sottostimare l'utilizzo totale della GPU; un dato mancante è indicato come non disponibile. Le GPU sono identificate per produttore. AMD e NVIDIA e le altre distribuzioni non sono state provate su hardware reale. Le metriche specifiche di Windows non hanno sempre un equivalente Linux: i file allocati del kernel sostituiscono gli handle; la virtualizzazione indica il supporto CPU. Capacità espresse in potenze di 1024, come nel riferimento Windows. Dischi, interfacce di rete, GPU e NPU vengono rilevati a ogni campione: non occorre riaprire l’app. Le cronologie vengono eliminate quando un dispositivo è rimosso o sostituito; il primo campione di un nuovo disco o NPU non inventa un utilizzo pari a zero.

La somiglianza visiva è una ricostruzione, non una corrispondenza pixel per pixel: i font disponibili e alcuni dati Linux differiscono. Se Segoe UI non è installato viene usato Noto Sans. Nessun font o asset Microsoft viene redistribuito. Il riferimento visivo di Prestazioni è la [guida TechRadar](https://www.techradar.com/how-to/how-to-use-the-redesigned-task-manager-in-windows-11s-2022-update).

## Comportamenti sospetti

La pagina Processi segnala in **Stato** i processi «Sospetto» (rischio alto) o «Da verificare» (rischio medio); il tooltip spiega il motivo. Scrivere «sospetto» nella ricerca mostra solo quelli. La riga in fondo riassume processi e avvisi di sistema; il suo tooltip elenca gli avvisi di sistema. Sono segnali euristici sui dati già raccolti, **non un antivirus**: non analizzano il contenuto dei file e non chiudono nulla da soli.

Controlli sui processi:
- nome da thread del kernel (`kworker`, `kthreadd`…) in un processo che non discende da kthreadd: funziona anche per i processi di altri utenti, perché usa solo nome e PID padre;
- eseguibile cancellato dopo l’avvio, fuori dalle cartelle di sistema (gli eseguibili sostituiti da un aggiornamento in `/usr` sono normali e ignorati);
- eseguibile in `/dev/shm` (alto) o in `/tmp`, `/var/tmp` (medio; le AppImage in `/tmp/.mount_*` sono escluse);
- riga di comando con shell remote (`/dev/tcp`, `nc -e`, script in linea con socket e shell), parametri da miner, base64 eseguito da una shell, `curl | sh`;
- connessioni o porte in ascolto tipiche di pool di mining e backdoor (3333, 4444, 14444…), lette ogni 5 secondi con `psutil.net_connections`;
- almeno un core intero usato per 2 minuti da un eseguibile fuori dalle cartelle di sistema.

Avvisi di sistema, ricontrollati ogni minuto: `~/.bashrc`, `.profile`, `.zshrc`, configurazione di fish, `~/.config/autostart`, unità systemd dell’utente e `crontab -l` che contengono gli stessi comandi sospetti o avviano programmi da cartelle temporanee. Le tastiere USB collegate dopo l’avvio dell’app vengono segnalate; rischio alto se lo stesso dispositivo è anche una memoria di massa (tipico delle chiavette BadUSB).

### Trappole nelle cartelle temporanee

All’avvio l’app crea tre **file trappola** (honeyfile o canary file): uno in `/tmp`, uno in `/var/tmp` e uno in `/dev/shm`, con nomi appetibili per chi cerca credenziali o portafogli (`.backup-credentials-….txt`, `wallet-….dat`, `.ssh-key-….bak`) e un suffisso casuale. Nessun programma legittimo ha motivo di aprirli, quindi ogni accesso è un segnale: un malware o un intruso che esplora le cartelle temporanee, o un ransomware che cifra i file che trova. L’elenco delle trappole attive è nel tooltip della riga in fondo alla pagina Processi: non aprirle, altrimenti scatta l’avviso.

- Lettura o apertura: rischio medio. Modifica, rinomina o cambio di permessi: rischio alto (comportamento da ransomware). Eliminazione: rischio medio, perché può essere una pulizia manuale; la trappola viene subito ricreata con un nuovo nome.
- La sorveglianza usa inotify, che non richiede permessi e scatta anche quando il file è aperto da altri utenti o da root (i file sono leggibili da tutti). inotify però non dice chi ha aperto il file: subito dopo l’evento l’app cerca il file tra i descrittori aperti dei processi. Il PID viene trovato solo se il processo è del tuo utente e tiene ancora il file aperto; in quel caso il processo è marcato anche nella tabella. Per un’attribuzione certa servirebbero fanotify o eBPF, che richiedono root.
- I file sono creati con `O_EXCL | O_NOFOLLOW` (un file o un collegamento già presente con quel nome non viene mai seguito né riusato) e con data di modifica nel futuro, così la pulizia automatica di systemd-tmpfiles (10 giorni per `/tmp`, 30 per `/var/tmp`) non li elimina.
- Alla chiusura dell’app o del server le trappole vengono eliminate. Dopo un arresto anomalo vengono rimosse al successivo avvio grazie al registro in `~/.cache/linux-task-manager/traps/`; si cancella solo un file normale del proprio utente che inizia con l’intestazione della trappola.
- Antivirus che scansionano `/tmp`, comandi come `grep -r /tmp` o programmi di pulizia possono far scattare le trappole. Per disattivarle aggiungere la riga `trappole` a `detection-ignore.txt`.

Con il monitoraggio remoto i controlli girano sul server, che vede le righe di comando complete, e viene trasmesso solo l’esito. I server senza questa funzione restano utilizzabili; la pagina chiede di aggiornarli.

Per i falsi allarmi creare `~/.config/linux-task-manager/detection-ignore.txt`: una riga per percorso dell’eseguibile, nome del processo, file di avvio (percorso completo), `crontab utente` o `trappole`; le righe che iniziano con `#` sono commenti.

Limiti che restano senza permessi di root: i processi che durano meno di un secondo possono sfuggire; per i processi di altri utenti il percorso dell’eseguibile e le connessioni non sono leggibili, quindi valgono solo i controlli su nome, riga di comando e CPU; un rootkit con privilegi di root può nascondersi dall’elenco dei processi.

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

In **Prestazioni → Collegamenti** sono visibili anche hub, dock e periferiche che non sono dischi o schede di rete. Selezionare una riga mostra la catena dei genitori e i dettagli; l’albero si aggiorna all’inserimento/rimozione conservando le espansioni. Il pulsante Copia collegamenti include tutti i dettagli. Dischi e schede USB mostrano anche il proprio percorso verso gli hub e il controller. Non sono esposti comandi di autorizzazione o reset.

Le **porte esterne** includono le prese vuote esposte dal firmware come `hotplug`. Canali dello stesso connettore sono raggruppati usando i riferimenti `connector`, `peer` o la posizione firmware `location`; il conteggio dipende dalla correttezza di questi dati e non comprende le porte di hub esterni. Se mancano gli abbinamenti, la pagina indica canali da abbinare anziché un totale fisico verificato. I collegamenti fissi (`removable=fixed` o `connect_type=hardwired`) e i controller/root hub hanno sezioni separate, chiuse inizialmente: quattro root hub e un controller USB4 non equivalgono a cinque prese USB. I dispositivi integrati in un dock esterno rimangono nel ramo del dock. La posizione degli altri dispositivi resta esplicitamente non disponibile. Server precedenti senza questi metadati mantengono l’albero, con conteggio prese non disponibile.

Una presa USB-C viene marcata **USB4 / Thunderbolt** quando esiste il collegamento sysfs dal router alla stessa presa; il dettaglio distingue il supporto dal link attivo (`usb4`, `tbt`, `none`). Se il controller è rilevato ma manca l’associazione alla presa, la pagina lo dichiara. Il nome del bus e la presenza del controller non sono usati per indovinare la presa o la certificazione Thunderbolt. Per il ThinkPad E16 Gen 2 Intel 21MA viene riportata la posizione Thunderbolt 4 dallo schema Lenovo, senza dedurre l’abbinamento ai canali del kernel.

Una prova fisica con due dispositivi invertiti può identificare le prese quando i metadati Type-C del firmware non bastano. L’app legge la calibrazione locale da `$XDG_CONFIG_HOME/linux-task-manager/usb-ports.json` (normalmente `~/.config/linux-task-manager/usb-ports.json`), verificando produttore, modello, radice sysfs e insieme esatto dei canali. La calibrazione identifica il supporto della presa, non un link Thunderbolt attivo, e non viene applicata dalla GUI al computer remoto. Sul computer verificato il 26 ottobre 2026: `usb2-port1 / usb3-port1` è la USB-C vicina alla cerniera; `usb2-port3 / usb3-port9` è la Thunderbolt 4 vicina alla USB-A. L’inversione tra hub e Nikon ha confermato entrambi i percorsi. Le prese non calibrate conservano una descrizione prudente dei riferimenti firmware.

USB-C è il connettore e non prova l’uso di Thunderbolt. La versione USB dichiarata dal dispositivo è distinta dalla velocità negoziata: un dispositivo USB 3 può lavorare su un segmento a 480 Mbit/s. I root hub non rappresentano link esterni attivi e non mostrano una velocità negoziata. Il numero nel nome `usb4` è il numero del bus, non la prova del protocollo USB4. Per USB4/Thunderbolt si usa il campo `generation` del kernel (4 = USB4); RX/TX sono velocità per corsia moltiplicate per il numero delle corsie, senza sommare invio e ricezione. Questi attributi non certificano il marchio commerciale Thunderbolt 4/5. I rami USB e Thunderbolt restano separati quando sysfs non fornisce un rapporto padre/figlio: un controller USB4 presente non implica che ogni hub USB appartenga a un tunnel Thunderbolt. Riferimenti: [ABI USB del kernel](https://www.kernel.org/doc/Documentation/ABI/stable/sysfs-bus-usb), [USB4 e Thunderbolt](https://docs.kernel.org/admin-guide/thunderbolt.html), [ABI dei router Thunderbolt](https://docs.kernel.org/admin-guide/abi-testing.html#symbols-under-sys-bus-thunderbolt).

La pagina Rete identifica l’hardware separatamente dal nome Linux dell’interfaccia: per esempio il modello della scheda compare sopra il grafico, mentre `wlan0` o `enp…` resta nel gruppo Scheda di rete. Produttore e modello provengono dalle proprietà udev o dai descrittori USB; per i dispositivi rimarchiati il fornitore dell’ID può essere diverso dal produttore dichiarato e viene mostrato separatamente. Non si indovina il chipset da MAC, driver o nome del dock. I dati hardware sono riletti quando cambia l’identità dell’interfaccia; in assenza di udev rimangono i descrittori e gli ID disponibili in sysfs. I server più vecchi continuano a funzionare, ma vanno aggiornati per inviare i nuovi dettagli hardware.
