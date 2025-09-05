import json

def readJson(fileName):
    data=[]
    try:
        with open(fileName, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    data.append(json.loads(line))
            return data
    except FileNotFoundError:
        print(f"Error: File '{fileName}' not found.")
        return None
    except Exception as e:
        print(f"Errore durante l'apertura del file: {e}")
        return None



    