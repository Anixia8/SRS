import streamlit as st
import pandas as pd
import tempfile, os

from data_prep import readJson
from classifier import classify_alerts
from random_response import response_generator

st.set_page_config(page_title="LLM4SOC Dashboard", layout="wide")

tab1, tab2 = st.tabs(["📊 Dashboard", "💬 ChatBot"])

with tab1:
    st.title("🔎 LLM4SOC – IDS Alert Triage Assistant")

    # ------------------------
    # Upload file
    # ------------------------
    uploaded_file = st.file_uploader("Carica il file degli alert (JSON Lines)", type=["json", "jsonl"])

    if uploaded_file is not None:
        try:
            # Salviamo temporaneamente il file caricato
            
            raw = uploaded_file.getvalue()  # non usare .read() due volte
            with tempfile.NamedTemporaryFile(dir="/tmp", suffix=".jsonl", delete=False) as f:
                f.write(raw)
                temp_path = f.name
            data = readJson(temp_path)


            # Classifica alert solo la prima volta
            if "classified_data" not in st.session_state:
                st.session_state.classified_data = classify_alerts(data)

            # Usa sempre gli stessi risultati già salvati
            df = pd.DataFrame(st.session_state.classified_data)


            st.success(f"✅ File caricato con {len(df)} alert classificati.")

            # ------------------------
            # Sidebar filters
            # ------------------------
            selected_class = st.sidebar.multiselect(
                "Filtra per classificazione",
                df["Classification"].unique(),
                default=[]  # <-- nessuna selezione iniziale
            )

            df_filtered = df.copy()

            if selected_class:
                df_filtered = df_filtered[df_filtered["Classification"].isin(selected_class)]

            if "priority" in df_filtered.columns:
                min_prio, max_prio = int(df_filtered["priority"].min()), int(df_filtered["priority"].max())
                prio_range = st.sidebar.slider("Filtra per priorità", min_prio, max_prio, (min_prio, max_prio))
                df_filtered = df_filtered[
                    (df_filtered["priority"] >= prio_range[0]) & (df_filtered["priority"] <= prio_range[1])
                ]

            if "source_ip" in df_filtered.columns:
                selected_ips = st.sidebar.multiselect("Filtra per IP sorgente", df_filtered["source_ip"].unique())
                if selected_ips:
                    df_filtered = df_filtered[df_filtered["source_ip"].isin(selected_ips)]

            # ------------------------
            # KPI metrics
            # ------------------------
            st.subheader("📊 Statistiche sugli alert")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Totale alert", len(df_filtered))
            if "Classification" in df_filtered.columns:
                col2.metric("False Positives", (df_filtered["Classification"] == "false positive").sum())
                col3.metric("Real Threats", (df_filtered["Classification"] == "real threat").sum())
                col4.metric("Uncertain", (df_filtered["Classification"] == "uncertain").sum())

            # ------------------------
            # Grafici
            # ------------------------
            if "Classification" in df_filtered.columns:
                st.subheader("📈 Distribuzione classificazioni")
                st.bar_chart(df_filtered["Classification"].value_counts())

            if "timestamp" in df_filtered.columns:
                try:
                    df_filtered["date"] = pd.to_datetime(df_filtered["timestamp"]).dt.date
                    st.subheader("📆 Trend nel tempo")
                    st.line_chart(df_filtered.groupby("date").size())
                except Exception:
                    st.warning("⚠️ Timestamp non in formato interpretabile per trend.")

            if "signature" in df_filtered.columns:
                st.subheader("🔝 Top 10 Signatures")
                st.bar_chart(df_filtered["signature"].value_counts().head(10))

            if "source_ip" in df_filtered.columns:
                st.subheader("🌐 Top 10 IP sorgenti")
                st.bar_chart(df_filtered["source_ip"].value_counts().head(10))

            # ------------------------
            # Tabella + Dettagli
            # ------------------------
            st.subheader("📋 Alert classificati")
            st.dataframe(df_filtered, use_container_width=True)

            st.subheader("🔍 Dettaglio alert")
            for i, row in df_filtered.iterrows():
                with st.expander(f"Alert {row.get('alert_id', i+1)} - {row.get('Classification', 'N/A')}"):
                    st.json(row.to_dict())

            # ------------------------
            # Download results
            # ------------------------
            st.download_button(
                label="📥 Scarica risultati (CSV)",
                data=df_filtered.to_csv(index=False).encode("utf-8"),
                file_name="classified_alerts.csv",
                mime="text/csv",
            )

        except Exception as e:
            st.error(f"Errore durante la classificazione: {e}")

    else:
        st.info("Carica un file JSON per iniziare.")


with tab2:
    # ------------------------
    # ChatBot
    # ------------------------
    st.title("💬 Chat Bot")

    # Inizializzazione chat
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Crea un contenitore per la cronologia della chat per gestirne lo scorrimento
    chat_placeholder = st.container(height=380) # Puoi regolare l'altezza come preferisci

    with chat_placeholder:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

    # Sposta l'input della chat al di fuori del contenitore della cronologia dei messaggi
    if prompt := st.chat_input("Fai una domanda"):
        # Aggiungi immediatamente il messaggio dell'utente per visualizzarlo
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Rigenera il contenitore con il nuovo messaggio dell'utente
        with chat_placeholder:
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                response = st.write_stream(response_generator()) # Assumi che response_generator() ritorni uno stream
            
        st.session_state.messages.append({"role": "assistant", "content": response})