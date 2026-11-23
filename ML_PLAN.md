# Studio: apprendimento automatico locale per processi e rete

Data: 22 novembre 2026. Stato: prima fase di implementazione dei prerequisiti; la nuova pipeline di ML automatico non è ancora attiva.

## Prima fase implementata

- `ProcessScanner`: boot ID/start tick, generazione dell'immagine, fingerprint dei metadati osservati, CPU in core equivalenti, thread, byte e velocità I/O separati. Gli eventi di exec invalidano i metadati; il confronto fra letture rileva anche cambiamenti senza proc connector. Un campione incoerente viene omesso senza perdere la generazione precedente. Il fingerprint non è un hash del contenuto del binario. Un exec identico nei metadati non è distinguibile quando il relativo evento non viene ricevuto.
- `Detector`: invalidazione delle regole statiche e della storia CPU su nuova immagine o evento exec. `rootservice` pubblica campioni completi e identità delle segnalazioni; `metrics` verifica compatibilità prima di usarli. Le generazioni locali del campionatore GUI e di quello root non vengono confrontate fra loro.
- `NetworkAnalyzer`: stato cumulativo per tupla e cookie del kernel, delta di socket attivi e residuo a chiusura. I socket già aperti stabiliscono il primo riferimento separatamente per TX/RX; quelli con SYN osservato includono il primo totale. Chiusure duplicate e snapshot tardivi non ricontano i byte. Stato bounded: dopo perdita o scadenza della cache i totali potenzialmente già contati vengono omessi; `flow_accounting_limited` indica questa condizione. Un contatore temporaneamente mancante mantiene conservativamente non disponibile il volume della relativa direzione nella finestra.
- `NetWatch`: associazione attuale tramite inode/FD e PIDFD; PID, data di avvio, eseguibile e istante della verifica disponibili separatamente dalla descrizione. Nessun nome rimasto in cache dopo una nuova analisi senza proprietario verificabile. Un socket chiuso, condiviso o troppo breve può restare non attribuito.
- `test_ml_foundation.py`: 19 regressioni, inclusi exec reali con PID invariato, reset delle cache, campione interrotto, separazione fra immagini root/GUI, contatori iniziali, TX/RX mancanti, socket paralleli/riutilizzati, chiusure tardive/duplicate, ripresa dopo limite della cache, SYN ricevuto durante la raccolta `ss` e protezione da durate/età negative dopo un arretramento dell'orologio.

Misura locale dopo le modifiche: cinque campioni consecutivi senza privilegi, circa 506 processi; mediana 39,60 ms wall clock e 39,08 ms CPU per `ProcessScanner.rows()`. È una misura del solo campionatore sul computer attuale, non dell'intero servizio o dell'efficacia ML.

Verifica finale: `.venv/bin/python -m pytest -q` — **169 test e 19 subtest superati**, in 54,78 secondi. Compilazione dei moduli modificati e `git diff --check` completati senza errori. Per rendere operative le modifiche nel servizio già installato serve rieseguire `sudo ./install-root-service.sh` dal progetto.

Restano i passi 2–6 sotto: snapshot sotto soglia, finestre con qualità e gestione di gap/cambi d'orologio, persistenza, training separato, promozione/rollback e valutazione. In particolare le aggregazioni file attuali usano ancora PID/data di avvio: la nuova raccolta dei bucket deve separarle anche per generazione exec. Il fit della vecchia Isolation Forest di rete continua nel percorso attuale; nessun nuovo modello per processo è stato attivato.

## Obiettivo e scelta

Il servizio deve raccogliere dati, costruire la baseline, addestrare e aggiornare i modelli automaticamente. L'utente non deve preparare dataset, etichettare processi, scegliere iperparametri o avviare il training. L'obiettivo è ordinare comportamenti insoliti dei processi attivi, mantenendo evidenze comprensibili. Un punteggio di anomalia non è una probabilità di malware.

Per la prima versione propongo due modelli separati: attività del processo/file e comportamento della rete. Riutilizzare inizialmente l'Isolation Forest già presente dietro un'interfaccia condivisa, confrontandolo in sviluppo con l'implementazione di riferimento scikit-learn e con semplici mediane/quantili. Passare alla libreria in produzione solo se il confronto giustifica dipendenze e consumo aggiuntivi. Non aggiungere reti neurali, modelli scaricati o classificatori di file a questo intervento.

Il primo lavoro è correggere identità, contabilità e qualità dei dati: un modello più complesso non corregge campioni sbagliati.

## Riscontri iniziali prima dell'implementazione

| Componente | Situazione verificata | Conseguenza per ML |
| --- | --- | --- |
| `netbehavior.py`, `IsolationForest`, `vector()` | Modello custom, 64 alberi, campione massimo 128; otto caratteristiche per destinazione IP:porta. | È già ML non supervisionato, ma non un modello del singolo processo. |
| `NetworkAnalyzer.analyze()` | Fit ogni 600 secondi dopo 200 vettori; conserva gli ultimi 3.000. Anche vettori sospetti entrano nella storia. I vettori possono riassumere le stesse due ore sovrapposte. | Servono timestamp, separazione fra campioni nuovi e baseline, deduplicazione e validazione temporale. Le prime 24 ore disabilitano la novità della destinazione, non l'intero training ML. |
| `netwatch.py`, `poll()` | Il fit è chiamato sotto il lock dell'analizzatore, nel lavoro del ciclo del servizio. | Spostare fit e valutazione del candidato in un processo separato; non attendere il training nella raccolta. |
| `netwatch.py`, `attribute()` | Cerca via `ss` i processi di un massimo di dieci anomalie con score almeno 40. Salva descrizioni testuali senza identità di avvio e scadenza esplicita. | La stringa non è un collegamento affidabile processo/connessione per costruire feature o correlazioni. |
| `detection.py`, `ProcessScanner` | Legge CPU, RSS, I/O combinato, PID/PPID. La cache dei metadati è indicizzata da PID e start tick. | `execve()` può cambiare eseguibile, argomenti e credenziali senza cambiare PID/start: invalidare cache e profilo a ogni nuova esecuzione osservata. Anche la cache delle regole statiche va aggiornata. |
| `ProcessScanner.rows()` | CPU normalizzata su tutti i core, I/O lettura/scrittura unificato; thread raccolti ma non esportati nella riga. | Esportare grandezze interpretabili e separate; `None` deve restare dato mancante. |
| `process_network.py` | NetHogs alimenta la GUI; la riga espone una velocità combinata, non un flusso strutturato completo al servizio root. | Non presumere che il servizio ML abbia già byte TX/RX e destinazioni per processo. |
| `NetworkAnalyzer.snapshot()` e `close()` | Il bucket dispositivo può ricevere delta di una connessione attiva e poi il suo totale finale. I volumi del profilo destinazione derivano invece dalle connessioni chiuse. | Unificare la contabilità: a chiusura aggiungere solo il residuo non ancora contabilizzato. Misurare anche connessioni lunghe senza duplicarle. |
| `filebehavior.py`, `poll()` | Conteggi bounded di modifiche, rinomine, eliminazioni e allarmi solo oltre soglia. | Aggiungere uno snapshot numerico anche sotto soglia: il training ha bisogno soprattutto dell'attività ordinaria. Non esiste ancora un sensore generalizzato delle letture sensibili. |
| `filewatch.py` | Identità tramite PIDFD e PID/data di avvio; copertura, limiti ed eventi persi. | Riutilizzare questi segnali di qualità; finestre incomplete non entrano nel training. |
| `rootservice.py`, `metrics.py`, `processes.py`, `app.py` | Protocollo di stato root-owned, motivi e notifiche per identità. | Estendere il protocollo con stato ML, copertura, versione modello ed evidenze; evitare notifiche ripetute per piccole variazioni numeriche. |

## Architettura proposta

```text
ProcessScanner + ExecWatcher + FileWatch + NetWatch
                |
                v
    identità verificate e qualità dei sensori
                |
                v
     finestre numeriche chiuse e versionate
          |                         |
          v                         v
  modello stabile              campioni candidati
  e regole attuali             con ritardo di ammissione
          |                         |
          v                         v
  evidenze e avvisi        worker: training + confronto
                                    |
                                    v
                           promozione oppure scarto
```

Il servizio root mantiene raccolta e identità. Un worker con privilegi ridotti riceve solo vettori numerici su un canale privato limitato. Il worker gestisce fit e scoring ML; il servizio continua a pubblicare dati ogni secondo, anche se il worker è lento o termina. I risultati tornano come dati strutturati, con identità, fine finestra e versione modello: risultati vecchi o relativi a processi terminati vengono scartati. Il worker non ha un canale per inviare segnali ai processi o comandi firewall.

### Identità e caratteristiche

- Identità runtime: boot ID, PID, start tick; aggiungere una generazione dell'esecuzione. PID e data di avvio restano nel protocollo della GUI, ma il profilo va reinizializzato su exec. Per il contesto del padre conservare anche la sua identità, non solo il numero PPID.
- Rete: registrare le tuple di connessione con direzione e, quando verificabile, proprietario corrente. Socket condivisi o connessioni troppo brevi possono restare non attribuiti. Il modello per destinazione continua a funzionare; la correlazione al processo richiede un'attribuzione certa. eBPF è un'eventuale estensione successiva, non una dipendenza iniziale obbligatoria.
- Modello processo: CPU in core equivalenti, RSS e variazione, letture/scritture separate, thread, durata, avvii figli, file distinti modificati/rinominati/eliminati e loro frequenza. Le letture sensibili e l'utilizzo GPU per processo richiedono raccolta ulteriore e restano fuori dalla prima versione ML.
- Modello rete: byte TX/RX e loro rapporto, numero e durata delle connessioni, destinazioni diverse, novità, regolarità, esiti DNS quando osservabili. Distinguere esplicitamente feature per destinazione da feature per processo.
- Usare finestre brevi chiuse di 30 secondi e aggregati di 5 minuti come parametri iniziali da verificare. Le finestre lunghe già usate dalle regole possono restare, ma non vanno contate come campioni nuovi indipendenti a ogni analisi.
- Per i file aggiornare accumulatori di bucket direttamente durante l'ingestione, prima che `FileBehavior` elimini le osservazioni dopo 15 secondi. Uno snapshot ogni 30 secondi della struttura attuale perderebbe eventi. Conteggi e insiemi FID bounded per finestra devono deduplicare lo stesso oggetto anche attraverso rinomine; perdita di dati o superamento del limite rende incompleta la relativa finestra.
- Aggiungere maschere di disponibilità e qualità: accessi negati, backend assenti, queue overflow, gap di raccolta, campioni iniziali. Usare modelli con insiemi di feature coerenti; non sostituire una durata sconosciuta o un contatore assente con un valore zero inventato.
- Conservare baseline aggregate per applicazione/versione dell'eseguibile quando i dati sono sufficienti e un modello generale per i programmi nuovi. Non creare un modello per ogni PID né usare solo il nome del processo come identità dell'applicazione. Le novità, da sole, non diventano allarmi ad alto rischio.

### Ciclo completamente automatico

1. **Raccolta iniziale:** regole e trappole operative; il modello nuovo raccoglie e mostra «Apprendimento». Obiettivo iniziale di ammissibilità: almeno 24 ore osservate e 2.000 finestre campionate con sufficiente varietà. Questi valori sono ipotesi da validare, non una garanzia di dati puliti né un'attesa fissa dopo la quale attivarsi comunque.
2. **Campioni candidati:** separare lo scoring corrente dalla baseline. Introdurre un ritardo di ammissione, escludere eventi con sensori incompleti e intervalli collegati ad allarmi; limitare il peso di una singola applicazione o attività ripetitiva. Un dominio nella lista delle eccezioni non certifica un campione come normale.
3. **Primo modello:** addestrare sui candidati ammissibili; usare un periodo di calibrazione successivo e separato per soglie e confronto contro regole/statistiche robuste. Il test finale per accettare una versione resta ulteriore e separato, mai usato per scegliere soglie o candidati. Se i dati non bastano o il confronto fallisce, continuare la raccolta senza interventi dell'utente.
4. **Aggiornamenti:** tentare ogni sei ore solo con un numero sufficiente di nuovi campioni; mantenere un riferimento storico e un limite al contributo dei dati recenti. Nessun reinserimento immediato nel training dei dati appena valutati.
5. **Promozione:** il candidato sostituisce il modello stabile solo dopo controlli di schema, valori finiti, risorse, coerenza delle fixture di regressione e comportamento sul periodo di calibrazione. Il test finale resta escluso dalla scelta automatica dei candidati. Conservare la versione precedente per ripristino automatico. Questi controlli non possono dimostrare che la baseline sia priva di malware.
6. **Guasti:** modello corrotto, versione incompatibile, worker interrotto o copertura scarsa portano allo stato «Dati insufficienti»/«Modello non disponibile», con regole ancora attive. Il riavvio non azzera silenziosamente la cronologia valida.

Il ritardo e il filtro riducono la contaminazione della baseline; non eliminano un malware già presente durante l'apprendimento o capace di imitare attività abituali. Per un classificatore di malware con efficacia misurabile servirebbero dati etichettati e una valutazione distinta.

### Punteggi, spiegazioni e azioni

Calibrare l'anomalia sul periodo di calibrazione e per contesto, invece di interpretare il punteggio grezzo dell'albero come rischio percentuale. Valutare persistenza su più finestre e accordo fra famiglie di segnali. File rinominati e numero totale di file modificati sono correlati e non vanno trattati come due prove indipendenti equivalenti.

Esempio di evidenza: «Questo processo ha rinominato 80 file in 30 secondi; il suo profilo precedente ne mostrava normalmente 0–2». Il motivo descrive il confronto osservato, senza attribuire all'albero una spiegazione causale che non fornisce. La GUI mostra stato, periodo osservato, copertura e versione; niente pulsante obbligatorio di training.

Il modello non deve abbassare gli allarmi deterministici delle trappole o cancellare i dati di un processo. Nella prima versione produce solo segnalazioni. Il blocco della rete e la terminazione automatica non fanno parte dello studio di implementazione iniziale.

### Persistenza e budget

Stato ML separato dalla baseline di rete esistente, con schema e unità di misura versionati: `/var/lib/linux-task-manager/ml/`, root-owned, accesso ristretto. Separare candidati, baseline ammessa, validazione e metadati dei modelli. Scritture atomiche e limiti di dimensione; non caricare artefatti dalla home o dal repository modificabile dall'utente.

Per l'implementazione custom proposta, rappresentare alberi e metadati come JSON numerico con validazione di profondità, numero nodi, feature e valori finiti. Evitare caricamento di oggetti Python arbitrari. Se si adotta scikit-learn, definire prima una serializzazione compatibile e il confine di fiducia: pickle/joblib possono eseguire codice durante il caricamento e le versioni diverse della libreria non hanno compatibilità garantita.

Non persistere contenuti di file, payload, argomenti completi o nomi di documenti nel nuovo archivio ML. Conservare vettori, identità tecniche minimizzate, qualità e tempi necessari. Durate locali su clock monotono; wall clock per date; boot ID e gestione esplicita di sospensioni/gap. La baseline di rete attuale conserva già metadati propri: questa proposta non ne cambia silenziosamente la politica.

Budget iniziali di accettazione, ancora da misurare: massimo 30.000 campioni selezionati, archivio fino a 128 MiB con eliminazione dei campioni oltre 14 giorni, memoria aggiuntiva del servizio entro 64 MiB e worker entro 256 MiB. Limitare il worker a una CPU, coda bounded e durata massima del job; misurare anche il tempo di scoring su centinaia di processi, non solo il fit. Il ciclo di raccolta non deve attendere lookup di rete o training ML.

### Prima misura locale

Benchmark del 22 novembre 2026 su dati numerici sintetici generati con seed 20261122, nel Python del progetto: 64 alberi, campione 128, tre ripetizioni per configurazione. Sono misure dell'algoritmo custom, non dell'intero servizio né della sua efficacia di rilevamento.

| Dataset sintetico | Mediana fit | Mediana scoring di 1.000 profili |
| --- | --- | --- |
| 3.000 righe × 8 caratteristiche | 39,26 ms | 50,42 ms |
| 30.000 righe × 20 caratteristiche | 55,23 ms | 46,57 ms |

Picco RSS dell'intero processo di benchmark: 67,96 MiB, inclusi Python, NumPy e i dati sintetici. Le differenze piccole fra le misure di scoring non sono una prova di maggiore velocità con più caratteristiche. Il campione per albero resta limitato a 128 anche con 30.000 righe disponibili: questo spiega perché il costo non cresce proporzionalmente al dataset. La prima misura rende plausibile una soluzione CPU leggera; restano da misurare raccolta, IPC, archivio, picchi e scoring con più modelli. Non è stata modificata alcuna baseline in esecuzione.

## Moduli e ordine di lavoro

| Passo | File interessati | Risultato verificabile |
| --- | --- | --- |
| 1. Correttezza dei dati | `detection.py`, `netwatch.py`, `netbehavior.py` | Exec/PID non confusi; byte contati una sola volta; dati mancanti e clock gestiti. |
| 2. Snapshot numerici | `filebehavior.py`, `filewatch.py`, nuovo `behavior_features.py` | Profili anche sotto soglia, finestre chiuse e quality gate. Non cambiare gli allarmi esistenti per costruire il dataset. |
| 3. Persistenza | Nuovo `behavior_store.py` | Candidati e baseline separati, quote, schema, recupero dopo riavvio e limiti disco. |
| 4. Modello e worker | Nuovi `anomaly_model.py`, `ml_worker.py` | Modello condiviso verificato, training automatico fuori dal loop root, confronto e ripristino. |
| 5. Integrazione | `rootservice.py`, `install-root-service.sh`, `metrics.py`, `processes.py`, `app.py` | Stato e spiegazioni ML, modelli disponibili automaticamente, nessuna notifica a ogni oscillazione di score. |
| 6. Valutazione | Nuove fixture di replay e test, oltre alle suite esistenti | Rapporto fra regole sole e regole+ML su stessi scenari e stessi periodi, prima della promozione agli avvisi. |

Il lavoro va consegnato in questi passi, senza attivare gli avvisi ML prima che i prerequisiti e la valutazione siano completati. La prima implementazione dovrebbe partire dal passo 1, non dall'aggiunta di un altro algoritmo.

## Verifica richiesta

- Identità: PID riciclato, exec con PID invariato, padre terminato, socket condivisi e connessioni brevi; nessuna attribuzione inventata.
- Contatori: trasferimento lungo con snapshot e chiusura conta esattamente gli stessi byte; mancanti e protocolli non osservati non diventano zeri.
- File: attività sotto soglia esportata; stesso FID dopo rinomina contato una volta; eventi all'inizio e alla fine dei bucket non persi o duplicati; pause prolungate del consumer non ricreano finestre complete inventate; eventi persi impediscono di ammettere la finestra al training.
- Dataset: quote per programma, campioni non duplicati, cambi di versione schema, riavvii e orologio alterato. Nessuna promozione su campioni appena usati per addestrare.
- Validazione temporale: tre periodi in ordine, training → calibrazione → test finale, con un intervallo su ogni confine almeno pari al massimo orizzonte delle feature (due ore se si mantengono quelle attuali). Preprocessing appreso solo sul training; soglie sul periodo di calibrazione; selezione di modelli, campioni e soglie mai sul test finale. Le fixture riutilizzate come controllo automatico non diventano per questo una prova di generalizzazione.
- Replay legittimi: browser/chat, streaming, backup, sincronizzazione, compilazione, aggiornamenti e cifratura volontaria. Simulazioni innocue separate: modifiche massive, shell figlia insolita, beacon, picchi e invii anomali. Non eseguire malware reale sul computer monitorato.
- Metriche: avvisi e notifiche per ora, latenza della segnalazione, quota di processi/socket attribuiti, finestre utilizzabili, CPU/RSS/disco e ritardo della raccolta. Misurare il vantaggio aggiunto del modello rispetto a regole e quantili; non dichiarare percentuali di rilevamento virus da queste sole prove.

## Fonti tecniche

- [scikit-learn: novelty/outlier detection e Isolation Forest](https://scikit-learn.org/stable/modules/outlier_detection.html): distinzione fra distribuzione insolita e classificazione, ipotesi sui dati di addestramento.
- [scikit-learn: data leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage): separazione dei dati prima di trasformazioni e apprendimento.
- [scikit-learn: model persistence](https://scikit-learn.org/stable/model_persistence.html#security-maintainability-limitations): fiducia negli artefatti e incompatibilità fra versioni. Le scelte architetturali e i budget sopra sono proposte per questo progetto, non prestazioni garantite da queste fonti.
