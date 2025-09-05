import json
import pandas as pd

def save_to_json(alerts_list, output_file):
    try:
        with open(output_file, 'w') as f:
            for alert in alerts_list:
                f.write(json.dumps(alert) + "\n")
        print(f"Risultati salvati in {output_file}")
    except Exception as e:
        print(f"Errore durante il salvataggio: {e}")

def save_to_csv(alerts_list, output_file):
    df = pd.DataFrame(alerts_list)
    df.to_csv(output_file, index=False)
    print(f"Risultati salvati in {output_file}")
