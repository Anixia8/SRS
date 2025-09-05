import json
import csv

def loadAttacks(fileCSV):
    """Carica gli intervalli di attacco dal file CSV."""
    attacks = []
    with open(fileCSV, 'r') as file:
        reader = csv.DictReader(file)
        for riga in reader:
            attacks.append({
                'scenario': str(riga['scenario']),
                'attackName': str(riga['attack']),
                'start': float(riga['start']),
                'end': float(riga['end'])
            })
    return attacks

def realAttacks(fileJSON, attacks, scenario, attackName):
    """Identifica gli allarmi che corrispondono a un attacco reale."""
    data = []
    for attack in attacks:
        if attack['scenario'] == scenario and attack['attackName'] == attackName:
            timeStart = attack['start']
            endTime = attack['end']
            print(f"Scenario: {attack['scenario']}, attacco: {attack['attackName']}, inizio: {timeStart}, fine: {endTime} ")
        
    try:
        with open(fileJSON, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    alert = json.loads(line)
                    timestamp = alert['LogData']['Timestamps'][0]
                    
                    # Confronta il timestamp con gli intervalli di attacco
                    is_real_attack = False
                    
                    if timeStart <= timestamp <= endTime:
                        is_real_attack = True
                        
                    
                    if is_real_attack:
                        data.append(alert)    
        return data
    except FileNotFoundError:
        print(f"Error: File '{fileJSON}' not found.")
        return None
    except Exception as e:
        print(f"Errore durante l'apertura del file: {e}")
        return None

def falseAttacks(fileJSON, attacks):
    data = []
    try:
        with open(fileJSON, 'r') as file:
            for line in file:
                if line:
                    alert = json.loads(line)
                    timestamp = alert['LogData']['Timestamps'][0]

                    is_real_attack = False

                    for attack in attacks:
                        if attack['start'] <= timestamp <= attack['end']:
                            is_real_attack = True
                    
                    if not is_real_attack:
                        data.append(alert)
        return data
    except FileNotFoundError:
        print(f"Error: File '{fileJSON}' not found.")
        return None
    except Exception as e:
        print(f"Errore durante l'apertura del file: {e}")
        return None

                    
