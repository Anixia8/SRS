import json
from langchain_google_vertexai import ChatVertexAI
import streamlit as st
import os

def answer_question(question: str) -> str:
    """Risponde alla domanda usando gli alert presenti in session_state.alerts_for_chat."""
    alerts = st.session_state.get("alerts_for_chat", [])
    if not alerts:
        return "Non ho ancora dati di alert in memoria. Carica un file nella tab Dashboard."

    # Limita la dimensione del contesto per sicurezza
    MAX_ALERTS = 300           # alza/abbassa in base al modello
    MAX_JSON_CHARS = 120_000   # limite “hard” per il prompt
    subset = alerts[:MAX_ALERTS]
    context_json = json.dumps(subset, ensure_ascii=False)

    if len(context_json) > MAX_JSON_CHARS:
        # taglio brutale, ma evita overflow
        context_json = context_json[:MAX_JSON_CHARS] + " ... [TRUNCATED]"

    system_instructions = """Sei un analista SOC. Ti fornisco un elenco di alert (JSON) con campi:
- timestamp, source_ip, signature, priority, payload_summary, detector
- più campi LLM: Classification, Explanation, NextSteps, Confidence, ecc.
Rispondi in modo conciso e cita gli alert rilevanti indicando, quando utile, il loro indice (posizione nella lista) o i valori chiave.
Se la domanda è ambigua, spiega cosa manca e proponi filtri chiari.
Se non trovi la risposta nei dati forniti, dillo esplicitamente.
"""

    prompt = f"""{system_instructions}

=== ALERT DATA (JSON, possibly truncated) ===
{context_json}
=== END DATA ===

Domanda dell'utente: {question}
Risposta:"""

    model = ChatVertexAI(
        model=os.getenv("LLM_MODEL", "gemini-1.5-flash-002"),
        location=os.getenv("VERTEX_LOCATION", "europe-west1"),
        temperature=0,
    )
    resp = model.invoke(prompt)
    # LangChain può restituire Message/AIMessage; gestiamo content/testo
    text = getattr(resp, "content", None) or str(resp)
    return text
