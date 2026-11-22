# Gestione attività Linux

App desktop Python + Qt che riprende disposizione, grafici e colori delle schede **Processi** e **Prestazioni** di Gestione attività di Windows 11. Prima versione sviluppata e verificata su CachyOS con GNOME/Wayland, con dati reali di questo computer.

## Avvio

```bash
git clone https://github.com/GiacomoCunardi2005/linux-task-manager.git
cd linux-task-manager
./start.sh
```

Il primo avvio crea un ambiente Python locale e installa Qt Essentials e psutil, se mancanti. Non richiede root. Su altre distribuzioni servono Python 3 con venv/pip e le librerie di sistema per Qt/Wayland o X11. Su Arch/CachyOS i prerequisiti sono `python`, `python-pip` e le normali librerie del desktop. L’app non apre porte di rete. Il servizio root è separato e opzionale.

## Avvio all’accensione nell’area di notifica

```bash
./install-desktop.sh
```

Aggiunge l’app al menu e la avvia a ogni login **nascosta nell’area di notifica** (tray), con l’opzione `--tray`. Su GNOME serve l’estensione AppIndicator, attiva su questo computer. Chiudere la finestra la nasconde e la sorveglianza continua; per uscire davvero usare **Esci** nel menu dell’icona. L’icona diventa gialla o rossa quando ci sono avvisi e ogni nuovo avviso compare come notifica; cliccarla riapre la finestra. Al logout l’app riceve SIGTERM, si chiude in modo pulito e rimuove le trappole. Per togliere solo l’avvio automatico: `./install-desktop.sh --no-autostart`.

## Servizio root (opzionale, consigliato)

L’interfaccia resta del tuo utente: una GUI Qt da root sarebbe rischiosa e su Wayland spesso non funziona. Il lavoro che richiede root lo fa un piccolo servizio di sistema senza interfaccia, avviato all’accensione:

```bash
sudo ./install-root-service.sh
```

- Vede **tutti i processi**, anche di root e di altri utenti: eseguibile, I/O disco, connessioni e tutti i controlli di sicurezza. L’app mostra questi dati e in fondo alla pagina Processi indica «Protezione root attiva».
- Sa **chi apre le trappole** grazie a fanotify (senza root il kernel restituisce PID 0) e crea le trappole a nome tuo, così un ransomware che gira come te può modificarle e viene scoperto.
- Controlla anche `crontab` di root. Le eccezioni del servizio sono in `/etc/linux-task-manager/ignore.txt`, modificabile solo da root: un file dell’utente permetterebbe a un malware dell’utente di spegnere i controlli.
- **Chiudere processi di root o di altri utenti**: «Termina attività» chiede la password di amministratore tramite polkit (`pkexec`), che resta valida per qualche minuto. Il servizio ricontrolla PID e data di avvio e rifiuta PID 1, i thread del kernel e se stesso. Non esiste un canale sempre aperto con cui altri programmi possano chiedere a root di chiudere processi.
- Il codice eseguito da root viene copiato in `/opt/linux-task-manager-root`, di proprietà di root: root non esegue mai file modificabili dal tuo utente. **Dopo ogni aggiornamento del progetto rilancia `sudo ./install-root-service.sh`.**
- Il servizio scrive i risultati ogni secondo in `/run/linux-task-manager/state.json` (di root, leggibile solo dal tuo gruppo). L’app li usa solo se il file è recente, di root e non modificabile da altri; altrimenti torna alla protezione base e ricrea le proprie trappole.
- L’unità systemd è limitata: file system di sola lettura tranne cartelle temporanee e home, capacità ridotte a quelle necessarie, `NoNewPrivileges`.

Comandi utili:

```bash
systemctl status linux-task-manager-root
journalctl -u linux-task-manager-root -n 30
sudo ./install-root-service.sh --uninstall
```

## Cosa funziona

- Processi: applicazioni raggruppate con PID espandibili, ricerca per nome/PID/utente, ordinamento numerico, CPU, memoria RSS, I/O disco, traffico TCP/UDP e stato; terminazione del singolo processo o di tutto il gruppo con conferma (processi di root o di altri utenti con password di amministratore e servizio root) e controllo dell’identità PID + data di avvio; segnalazione euristica dei comportamenti sospetti.
- CPU totale e per processore logico, frequenza, processi, thread, file allocati dal kernel, uptime, topologia e cache.
- RAM: velocità configurata in MT/s, slot utilizzati, tipo DDR, formato e capacità dei moduli, memoria installata e utilizzabile, impegno/limite Linux, slab recuperabile e non recuperabile, cache, buffer, memoria condivisa e swap; grafico e composizione della memoria.
- Dischi: rilevamento automatico di inserimento/rimozione, tempo di attività, letture/scritture, latenza media, capacità, modello, montaggi e bus. USB: velocità negoziata, versione dichiarata e prodotto; NVMe/PCIe: velocità e larghezza del collegamento.
- Rete: produttore e modello della scheda da udev/sysfs, ID hardware, fornitore dell’ID se diverso dal produttore dichiarato, interfaccia Linux, bus e posizione; invio/ricezione effettivi, scala automatica, indirizzi IPv4/IPv6/MAC, MTU, driver, velocità e duplex Ethernet. Wi-Fi: SSID, BSSID, standard 4/5/6/6E/7 quando riconoscibile, banda, frequenza, canale, larghezza, segnale e bitrate radio RX/TX (richiede il comando opzionale `iw`). Le velocità negoziate non rappresentano la velocità Internet.
- Collegamenti: albero USB con root hub, hub intermedi e dispositivi, velocità negoziata per ciascun segmento, controller, porte e ID USB. Router USB4 e Thunderbolt separati, generazione del kernel, autorizzazione e velocità RX/TX calcolate dalle corsie, quando disponibili.
- NPU: acceleratori Linux `/sys/class/accel`, utilizzo Intel dal tempo dei job, memoria residente, frequenza e stato energetico dove esposti dal driver.
- GPU DRM: motori accessibili tramite fdinfo, utilizzo sysfs quando presente, VRAM e frequenza se esposte dal driver.
- Cronologia reale di 60 secondi, campionamento ogni secondo, pausa della visualizzazione, copia informazioni e navigazione comprimibile. Trascina la barra del titolo per spostare; doppio clic per ingrandire; angolo inferiore destro per ridimensionare.

La cronologia si riempie dopo l'avvio: non contiene campioni simulati. La pausa congela la visualizzazione; il campionamento continua e al ripristino viene mostrata la cronologia aggiornata. Il menu `…` attiva i grafici per processore logico.

## Limiti di questa prima versione

Il menu richiudibile contiene solo Processi e Prestazioni. La terminazione invia SIGTERM al processo selezionato oppure, se è selezionato un gruppo, a ciascun suo PID dopo una sola conferma che li elenca; ogni PID è ricontrollato con la data di avvio. Non forza la chiusura né termina automaticamente i discendenti. Può causare la perdita dei dati non salvati. PID 1, i thread del kernel e l’app stessa sono protetti; i processi altrui richiedono il servizio root e la password di amministratore.

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

### Trappole

All’avvio vengono creati **file trappola** (honeyfile o canary file) con nomi appetibili e un suffisso casuale: in `/tmp` (`.backup-credentials-….txt`), `/var/tmp` (`wallet-….dat`), `/dev/shm` (`.ssh-key-….bak`), nella home (`.password-backup-….txt`), in Documenti (`.contratti-riservati-….docx`), Scrivania (`.portafoglio-crypto-….txt`), Scaricati (`.fatture-….pdf`) e in `~/.ssh` (`.backup-key-….old`). Le cartelle personali sono lette da `~/.config/user-dirs.dirs`, quindi funzionano anche con i nomi italiani. Nelle cartelle personali i file sono nascosti (iniziano con il punto) e leggibili solo da te: gli indicizzatori del desktop (Tracker, Baloo) saltano i file nascosti, mentre ransomware e intrusi li elencano comunque, di solito per primi. Nessun programma legittimo ha motivo di aprirli, quindi ogni accesso è un segnale: un malware o un intruso che cerca credenziali, o un ransomware che cifra i file che trova. L’elenco delle trappole attive è nel tooltip della riga in fondo alla pagina Processi: non aprirle, altrimenti scatta l’avviso.

- Lettura o apertura: rischio medio. Modifica, rinomina o cambio di permessi: rischio alto (comportamento da ransomware). Eliminazione: rischio medio, perché può essere una pulizia manuale; la trappola viene subito ricreata con un nuovo nome.
- La sorveglianza usa inotify, che non richiede permessi e scatta anche quando il file è aperto da altri utenti o da root (i file sono leggibili da tutti). inotify però non dice chi ha aperto il file. Con il servizio root fanotify indica sempre il PID e il nome del processo; senza, l’app cerca il file tra i descrittori aperti e trova il PID solo se il processo è del tuo utente e tiene ancora il file aperto. Il processo identificato è marcato anche nella tabella.
- I file sono creati con `O_EXCL | O_NOFOLLOW` (un file o un collegamento già presente con quel nome non viene mai seguito né riusato) e con data di modifica nel futuro, così la pulizia automatica di systemd-tmpfiles (10 giorni per `/tmp`, 30 per `/var/tmp`) non li elimina.
- Alla chiusura dell’app o del servizio le trappole vengono eliminate. Dopo un arresto anomalo vengono rimosse al successivo avvio grazie al registro in `~/.cache/linux-task-manager/traps/` (servizio root: `/var/lib/linux-task-manager/traps/`); si cancella solo un file normale del proprio utente che inizia con l’intestazione della trappola.
- Possono far scattare le trappole: antivirus, programmi di **backup** o sincronizzazione della home, comandi come `grep -r ~` e programmi di pulizia. Con il servizio root, se il processo che le apre ha un nome presente nella lista delle eccezioni (per esempio `deja-dup`), l’accesso non viene segnalato. Per disattivare le trappole aggiungere la riga `trappole` alla lista delle eccezioni.

### Estensioni degli agenti AI (Claude Code, Codex)

Hook, skill, plugin e server MCP degli agenti di programmazione sono codice che gira con i tuoi permessi, a volte prima che il modello o tu ve ne accorgiate. Ogni 5 minuti (rileggendo solo i file cambiati) vengono controllati:

- **hook** di `~/.claude/settings*.json`, dei progetti (`.claude/settings*.json`) e dei plugin installati di Claude e Codex: rischio alto se leggono credenziali e usano la rete, eseguono programmi da cartelle temporanee o contengono shell remote o miner;
- **skill e comandi**: i comandi `` !`…` `` che Claude Code esegue *prima* di passare il testo al modello (contesto dinamico), con le stesse regole; `allowed-tools: Bash(*)` nell’intestazione di una skill (qualsiasi comando senza conferma);
- **server MCP** di `~/.claude.json`, dei progetti (`.mcp.json`, `.codex/config.toml`), di Codex e dei plugin: comandi pericolosi, pacchetti avviati con `npx`/`uvx`/`bunx`/`pnpm dlx` **senza versione fissata** o con `@latest` (a ogni avvio viene eseguita l’ultima versione pubblicata, anche se compromessa), collegamenti `http` non cifrati;
- **impostazioni** che tolgono le protezioni: Codex con `sandbox_mode = "danger-full-access"` o `approval_policy = "never"`, Claude Code con `bypassPermissions`;
- **file dei repository** noti a Claude o Codex: `.env` che imposta `CODEX_HOME` (tecnica della CVE-2025-61260); `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` o `.cursorrules` nella cartella dei download.

Viene salvata un’impronta di ogni hook, server MCP e comando dinamico (`~/.cache/linux-task-manager/agents.json`, servizio root: `/var/lib/linux-task-manager/agents.json`). Se uno compare o cambia dopo il primo controllo, l’avviso «nuovi o modificati dall’ultimo controllo» resta per 24 ore: difende dal *rug pull*, cioè un’estensione approvata quando era innocua e cambiata dopo. Un aggiornamento dei plugin fatto da te produce lo stesso avviso. Per escludere un elemento aggiungere alla lista delle eccezioni l’etichetta mostrata (per esempio `Server MCP «playwright» (~/.claude.json)`); la riga `agenti` disattiva tutto il controllo. Non vengono letti i *contenuti* restituiti dai server MCP in esecuzione (descrizioni degli strumenti), quindi l’avvelenamento delle descrizioni non è rilevabile da qui.

### Anomalie di rete (servizio root)

Il servizio root osserva **solo il comportamento** delle comunicazioni: nessun elenco di server malevoli, nessuna firma, nessun modello addestrato su malware. Ogni comunicazione riceve un **punteggio 0–100** che combina indicatori indipendenti (un indicatore da solo resta basso; più indicatori insieme lo alzano). Il pulsante **Anomalie di rete** della pagina Processi mostra la classifica con le evidenze di ogni voce; solo i punteggi da 70 in su diventano avvisi («Da verificare», da 90 «Sospetto»). È un elenco di ciò che merita uno sguardo, non una diagnosi.

Fonti, tutte dal kernel e senza leggere contenuti: cattura filtrata con BPF dei soli pacchetti DNS e degli avvii di connessione TCP (orari esatti del kernel); eventi di chiusura dei socket (`sock_diag`) con i byte finali di ogni connessione, anche se dura 200 ms; contatori di `ss` ogni 5 secondi per le connessioni lunghe; `loginctl` per sapere se l’utente è inattivo.

Indicatori:
- **Beaconing**: contatti a intervalli regolari verso la stessa destinazione, tollerando jitter e battiti mancati; contano la regolarità e il coefficiente di variazione degli intervalli (il traffico casuale ha CV intorno a 0,27, un beacon sotto 0,2), dimensioni quasi costanti, persistenza nelle ore, richiesta DNS prima di ogni connessione. Vale anche per i «battiti» dentro una sola connessione lunga. Un ritmo presente da più di 3 giorni (posta, sincronizzazione, chat) è considerato un’abitudine e pesa molto meno.
- **DGA**: molti domini diversi inesistenti (NXDOMAIN) in 15 minuti, con nomi casuali (entropia, cifre, poche vocali), di lunghezza simile e mai visti prima.
- **Tunnel DNS**: molti sottodomini lunghi, diversi e ad alta entropia verso lo stesso dominio, etichette da dati codificati, richieste TXT/NULL.
- **Volumi**: molti dati inviati rispetto a quelli ricevuti (possibile esfiltrazione); picchi del dispositivo in connessioni, destinazioni diverse o byte inviati rispetto alla propria storia (z robusto con mediana e MAD).
- **Destinazioni**: destinazioni mai viste (dopo le prime 24 ore), connessioni brevissime e ripetute.
- **Correlazione temporale**: attività mentre l’utente è inattivo, DNS seguito dalla connessione.
- **Isolation Forest** (non supervisionato) addestrato ogni 10 minuti sui profili delle destinazioni osservati su questo computer: segnala quelle che si isolano con poche suddivisioni casuali.

La baseline locale (destinazioni, domini, ritmi abituali, storia del dispositivo, profili per l’Isolation Forest) è in `/var/lib/linux-task-manager/network.json`; le prime 24 ore servono a costruirla. Il processo responsabile viene cercato solo per le voci con punteggio da 40 in su. Limiti: DNS cifrato (DoH/DoT) e traffico QUIC/UDP non sono visibili; il contenuto cifrato non viene letto; un malware che imita perfettamente il traffico abituale può passare inosservato; anche programmi legittimi possono essere periodici o inviare molti dati, per questo conta la combinazione di indicatori. Le prove simulate tengono il traffico di navigazione casuale sotto 40 e un beacon C2 nuovo sopra 90.

### Processi di breve durata

Il kernel avvisa a ogni avvio di programma (proc connector), quindi anche i processi che durano meno del campionamento di 1 secondo vengono controllati: l’app legge `/proc` subito dopo l’avvio e un processo terminato in un millisecondo con un eseguibile in `/dev/shm` viene comunque segnalato. Su questo kernel funziona anche senza root; per i processi di altri utenti senza servizio root l’eseguibile non è leggibile e valgono i controlli su nome e riga di comando. Sono controllati anche i file di avvio di sistema (`/etc/cron.d`, `/etc/crontab`, unità systemd in `/etc/systemd/system`, `/etc/xdg/autostart`, `/etc/profile.d`) e `/etc/ld.so.preload`, che carica una libreria in ogni programma ed è una tecnica tipica dei rootkit.

Per i falsi allarmi senza servizio root creare `~/.config/linux-task-manager/detection-ignore.txt` (con il servizio root: `/etc/linux-task-manager/ignore.txt`): una riga per percorso dell’eseguibile, nome del processo, file di avvio (percorso completo), `crontab utente` o `trappole`; le righe che iniziano con `#` sono commenti.

Limiti: senza servizio root, per i processi di altri utenti eseguibile e connessioni non sono leggibili e il PID di chi apre una trappola resta spesso sconosciuto. Anche con il servizio root, un rootkit nel kernel può nascondersi dall’elenco dei processi, e un processo che termina prima che `/proc` venga letto (meno di circa un millisecondo) può sfuggire.

## Verifica

```bash
.venv/bin/python -m unittest -v test_metrics test_ui test_processes test_hardware test_process_network test_detection test_rootservice test_agents test_netbehavior test_netwatch
```

Test della contabilizzazione CPU, reset dei contatori, coerenza dei dati Linux e interazione delle viste Qt (risorse, pausa, processori logici, copia, finestra compatta). La cartella locale `reference/` non viene pubblicata: può contenere schermate con dati del computer e riferimenti esterni. I test UI producono schermate reali in `reference/linux-*.png` usando Qt offscreen.

Per rimuovere il collegamento dal menu e l’avvio automatico, eliminare `~/.local/share/applications/linux-task-manager.desktop` e `~/.config/autostart/linux-task-manager.desktop`. Il progetto e le dipendenze restano interamente in questa cartella.

La pagina Processi è verificata anche con ricerca letterale, ordinamento numerico, selezione stabile, pausa e annullamento/conferma della terminazione; il test dei segnali termina solo un sottoprocesso di prova. Le icone dei processi provengono dai file `.desktop` e dal tema di icone installato. Per fissare l’app alla barra, installare il collegamento e scegliere «Aggiungi ai preferiti» dal menu dell’icona.

Fonte visiva aggiuntiva: [schermata Windows 11 di Lonely Mobiler](https://loumo.jp/archives/28065).

I dettagli hardware della RAM si leggono una sola volta dalla cache udev (`udevadm info` sul dispositivo DMI), senza sudo. Su sistemi senza udev o con firmware incompleto restano «Non disponibile». La velocità configurata non viene sostituita dalla velocità massima nominale. «Riservata al sistema» è la differenza tra RAM installata secondo il firmware e MemTotal Linux, non una misura separata della sola riserva hardware. I valori Impegnata/limite e slab sono contatori Linux, diversi dai pool di Windows.

La velocità USB proviene dal collegamento attuale in sysfs, non dalla velocità massima stampata sul dispositivo; il tipo resta «Disco USB» perché alcuni adattatori/chiavette dichiarano erroneamente il flag di rotazione. L’app non monta, formatta né scrive sui dispositivi. I dettagli NPU attualmente supportano i contatori sysfs Intel; le altre NPU riconosciute restano visibili con i dati disponibili. Se mancano `iw`, permessi o contatori del driver, i campi interessati restano non disponibili. I dettagli Wi-Fi possono contenere SSID, BSSID e indirizzi locali: le schermate di test in `reference/` rimangono escluse da Git.

In **Prestazioni → Collegamenti** sono visibili anche hub, dock e periferiche che non sono dischi o schede di rete. Selezionare una riga mostra la catena dei genitori e i dettagli; l’albero si aggiorna all’inserimento/rimozione conservando le espansioni. Il pulsante Copia collegamenti include tutti i dettagli. Dischi e schede USB mostrano anche il proprio percorso verso gli hub e il controller. Non sono esposti comandi di autorizzazione o reset.

Le **porte esterne** includono le prese vuote esposte dal firmware come `hotplug`. Canali dello stesso connettore sono raggruppati usando i riferimenti `connector`, `peer` o la posizione firmware `location`; il conteggio dipende dalla correttezza di questi dati e non comprende le porte di hub esterni. Se mancano gli abbinamenti, la pagina indica canali da abbinare anziché un totale fisico verificato. I collegamenti fissi (`removable=fixed` o `connect_type=hardwired`) e i controller/root hub hanno sezioni separate, chiuse inizialmente: quattro root hub e un controller USB4 non equivalgono a cinque prese USB. I dispositivi integrati in un dock esterno rimangono nel ramo del dock. La posizione degli altri dispositivi resta esplicitamente non disponibile.

Una presa USB-C viene marcata **USB4 / Thunderbolt** quando esiste il collegamento sysfs dal router alla stessa presa; il dettaglio distingue il supporto dal link attivo (`usb4`, `tbt`, `none`). Se il controller è rilevato ma manca l’associazione alla presa, la pagina lo dichiara. Il nome del bus e la presenza del controller non sono usati per indovinare la presa o la certificazione Thunderbolt. Per il ThinkPad E16 Gen 2 Intel 21MA viene riportata la posizione Thunderbolt 4 dallo schema Lenovo, senza dedurre l’abbinamento ai canali del kernel.

Una prova fisica con due dispositivi invertiti può identificare le prese quando i metadati Type-C del firmware non bastano. L’app legge la calibrazione locale da `$XDG_CONFIG_HOME/linux-task-manager/usb-ports.json` (normalmente `~/.config/linux-task-manager/usb-ports.json`), verificando produttore, modello, radice sysfs e insieme esatto dei canali. La calibrazione identifica il supporto della presa, non un link Thunderbolt attivo,. Sul computer verificato il 26 ottobre 2026: `usb2-port1 / usb3-port1` è la USB-C vicina alla cerniera; `usb2-port3 / usb3-port9` è la Thunderbolt 4 vicina alla USB-A. L’inversione tra hub e Nikon ha confermato entrambi i percorsi. Le prese non calibrate conservano una descrizione prudente dei riferimenti firmware.

USB-C è il connettore e non prova l’uso di Thunderbolt. La versione USB dichiarata dal dispositivo è distinta dalla velocità negoziata: un dispositivo USB 3 può lavorare su un segmento a 480 Mbit/s. I root hub non rappresentano link esterni attivi e non mostrano una velocità negoziata. Il numero nel nome `usb4` è il numero del bus, non la prova del protocollo USB4. Per USB4/Thunderbolt si usa il campo `generation` del kernel (4 = USB4); RX/TX sono velocità per corsia moltiplicate per il numero delle corsie, senza sommare invio e ricezione. Questi attributi non certificano il marchio commerciale Thunderbolt 4/5. I rami USB e Thunderbolt restano separati quando sysfs non fornisce un rapporto padre/figlio: un controller USB4 presente non implica che ogni hub USB appartenga a un tunnel Thunderbolt. Riferimenti: [ABI USB del kernel](https://www.kernel.org/doc/Documentation/ABI/stable/sysfs-bus-usb), [USB4 e Thunderbolt](https://docs.kernel.org/admin-guide/thunderbolt.html), [ABI dei router Thunderbolt](https://docs.kernel.org/admin-guide/abi-testing.html#symbols-under-sys-bus-thunderbolt).

La pagina Rete identifica l’hardware separatamente dal nome Linux dell’interfaccia: per esempio il modello della scheda compare sopra il grafico, mentre `wlan0` o `enp…` resta nel gruppo Scheda di rete. Produttore e modello provengono dalle proprietà udev o dai descrittori USB; per i dispositivi rimarchiati il fornitore dell’ID può essere diverso dal produttore dichiarato e viene mostrato separatamente. Non si indovina il chipset da MAC, driver o nome del dock. I dati hardware sono riletti quando cambia l’identità dell’interfaccia; in assenza di udev rimangono i descrittori e gli ID disponibili in sysfs.
