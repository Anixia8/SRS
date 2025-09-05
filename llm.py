import os
from pydantic import BaseModel, Field
from typing_extensions import Literal,List
from langchain.chat_models import init_chat_model
from fastapi import FastAPI, UploadFile, HTTPException
from dataclasses import dataclass, asdict
from typing import Optional
from langchain_google_vertexai import ChatVertexAI

import random

class RequiredOutput(BaseModel):
    Classification:Literal["false positive","real threat"] = Field(description="La classificazione dell'alert decidere se è un real threat o un falso positivo")
    Explanation:str = Field(description = "Spiegazione del perchè è stata data quella classificazione, e cosa ti ha spintyo a classificarlo in quel modo.")
    number_id:int= Field(description="number_id associato all'alert fornito")
class RequiredOutputList(BaseModel):
    classification_list: List[RequiredOutput] =Field(description="Una lista di RequiredOutput con all'interno la classificazione di ognuno degli alert e la propria spiegazione. Ongi alert è associato al proprio number_id")


# funziona sia con Pydantic v1 che v2
def to_mapping(items):
    out = {}
    for m in items:
        # escludo number_id dal valore
        if hasattr(m, "model_dump"):  # Pydantic v2
            data = m.model_dump(exclude={"number_id"})
        else:                         # Pydantic v1
            data = m.dict(exclude={"number_id"})
        out[m.number_id] = data
    return out



def classify_alert(alert):
    prompt=f"""Sei un esperto di sicurezza informatica.
    Dato un alert devi deciderere se è un caso 'Falso_positivo' o 'Vera_minaccia' fornendo anche una spiegazione concisa sulla motivazione della tua scelta.

    Alert: 
    {alert}
    """
    model = init_chat_model("gemini", model_provider="ollama")

    model_output = model.with_structured_output(RequiredOutput).invoke(prompt)
    return model_output

def mock_llm(elemento):
    cl = random.choice(
        [
            "real threat",
            "false positive",
            "uncertain"
        ]
    )
    
    result = RequiredOutput(classification=cl, explanation="Ti devi fida")
    return result

def classify_all_alerts(alert_list):

    for i,alert in enumerate(alert_list,start=1):
        alert['number_id']=i


    prompt=f"""Sei un esperto di sicurezza informatica.
    Dato una lista di alert devi deciderere se è un caso 'Falso_positivo' o 'Vera_minaccia' fornendo anche una spiegazione sulla motivazione della tua scelta indicando i le cose che ti hanno portato a fornire quella classificazione.
    Per fornire una classificazione di un alert teni in considerazione anche gli alter che potrebbero precederlo o venire dopo.
    Inoltre fai particolarmente attenzione ai seguenti attacchi:
    1. Network scans

Cosa fa: scandaglia un intera rete cercando host attivi (ping sweep, ARP scan, ecc.).

Come riconoscerlo:

Nei log firewall/IDS: tante richieste ICMP/ARP verso IP consecutivi.

Pattern di connessioni brevi a molte destinazioni.

Alert tipici: “Ping sweep detected”, “Portscan”.

2. Service scans

Cosa fa: dopo aver trovato gli host, interroga le porte per capire quali servizi (HTTP, SSH, FTP, ecc.) sono attivi.

Come riconoscerlo:

Nei log IDS: connessioni ripetute a molte porte dallo stesso IP.

Nei log di sistema: tentativi di handshake incompleti o connessioni rifiutate in serie.

Alert: “Port scan TCP/UDP”.

3. Dirb (directory brute forcing)

Cosa fa: prova a indovinare cartelle e file nascosti su un web server (es. /admin, /backup.zip).

Come riconoscerlo:

Nei log webserver: tante richieste 404/403 in rapida sequenza.

User-Agent sospetti o tool noti.

Alert: “Excessive 404 responses”.

4. Wpscan

Cosa fa: scanner per WordPress, cerca plugin vulnerabili, utenti, versioni.

Come riconoscerlo:

Nei log Apache/Nginx: richieste a /wp-admin/, /xmlrpc.php, /wp-content/plugins/.

Accessi da IP unici che colpiscono solo URL legati a WordPress.

Alert: “WordPress brute-force attempt”.

5. Webshell

Cosa fa: file caricato sul server che permette di eseguire comandi (es. shell.php).

Come riconoscerlo:

Nei log webserver: upload di file in aree scrivibili.

Analisi file: script PHP/ASP insoliti.

Monitoraggio runtime: processo web che esegue comandi di sistema.

Alert: “Suspicious file upload / Webshell activity”.

6. Cracking

Cosa fa: tentativo di indovinare password (brute force, dictionary attack).

Come riconoscerlo:

Nei log di autenticazione: molti tentativi falliti dallo stesso IP.

Nei sistemi SIEM: eventi di login anomali distribuiti su più account.

Alert: “Brute force attack detected”.

7. Reverse shell

Cosa fa: il sistema compromesso apre una connessione in uscita verso l’attaccante, dando accesso remoto.

Come riconoscerlo:

Log di rete: connessioni TCP/UDP in uscita verso host insoliti.

Processi locali: shell (bash, cmd) con connessioni di rete aperte.

Alert: “Suspicious outbound connection”.

8. Privilege escalation

Cosa fa: da utente normale a root/admin sfruttando vulnerabilità o configurazioni sbagliate.

Come riconoscerlo:

Nei log sistema: cambi ruolo utente inattesi, uso di sudo o exploit noti.

Alert EDR: exploit escalation (es. buffer overflow, exploit kernel).

Indicatori: accesso a file solo root, modifiche a servizi critici.

9. Service stop

Cosa fa: interruzione di un servizio (es. spegnere firewall, antivirus, DB) per agevolare l’attacco o causare DoS.

Come riconoscerlo:

Nei log sistema: messaggi di arresto servizio non pianificati.

Alert SIEM: “Critical service stopped”.

Assenza improvvisa di log da un componente che prima loggava regolarmente.

10. Dnsteal

Cosa fa: esfiltra dati usando query DNS, nascondendo informazioni sensibili nei nomi di dominio.

Come riconoscerlo:

Log DNS: richieste con stringhe molto lunghe o strane (es. a1b2c3data.exfil.com).

Volume anomalo di query verso un singolo dominio.

Alert IDS: “DNS tunneling detected”.

    Alert: 
    {alert_list}

You MUST return the required output for ALL alerts in the list
    """
    #model = init_chat_model("mistral", model_provider="ollama")

    model = ChatVertexAI(
        model=os.getenv("LLM_MODEL", "gemini-1.5-flash"),
        location=os.getenv("VERTEX_LOCATION", "europe-west1"),
        temperature=0,
    )

    model_output = model.with_structured_output(RequiredOutputList).invoke(prompt)
    classification_list=model_output.classification_list

    classification_dict=to_mapping(classification_list)

    print(classification_dict)
    new_alert_list=[]
    for alert in alert_list:
        temp=alert|classification_dict[alert['number_id']]
        temp.pop("number_id")
        new_alert_list.append(temp)
    print(new_alert_list)
    return new_alert_list


