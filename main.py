from data_prep import readJson
from classifier import classify_alerts
from data_saver import save_to_json, save_to_csv
from filterJson import loadAttacks, realAttacks, falseAttacks

if __name__=="__main__":
    test_file="C:\\Users\\anixi\\Desktop\\Uni\\Scalable\\dataset\\ait_ads\\fox_aminer.json"
    fileCSV = "C:\\Users\\anixi\\Desktop\\Uni\\Scalable\\dataset\\labels.csv"
    #data=readJson(test_file)
    #classify_data = classify_alerts(data)
    #for d in classify_data:
    #    print (d["classification"])
    #print(classify_data[0])
    #save_to_json(classify_data, "classified_alerts_json.json")
    #save_to_csv(classify_data, "classified_alerts_csv.csv")

    attacks = loadAttacks(fileCSV)
    result1 = realAttacks(test_file, attacks, "fox", "network_scans")
    result2 = realAttacks(test_file, attacks, "fox", "wpscan")
    #result3 = realAttacks(test_file, attacks, "fox", "service_scans")
    #result4 = realAttacks(test_file, attacks, "fox", "dirb")
    #result5 = realAttacks(test_file, attacks, "fox", "webshell")
    #result6 = realAttacks(test_file, attacks, "fox", "cracking")
    #result7 = realAttacks(test_file, attacks, "fox", "reverse_shell")
    #result8 = realAttacks(test_file, attacks, "fox", "privilege_escalation")
    #result9 = realAttacks(test_file, attacks, "fox", "service_stop")
    result0 = realAttacks(test_file, attacks, "fox", "dnsteal")

    tot = readJson(test_file)

    save_to_json(result1, "fox_networkscan_alerts.json")
    print(f"Sono stati salvati {len(result1)} alarm reali su {len(tot)}.")

    save_to_json(result2, "fox_wpscan_alerts.json")
    print(f"Sono stati salvati {len(result2)} alarm reali su {len(tot)}.")

    save_to_json(result0, "fox_dnsteal_alerts.json")
    print(f"Sono stati salvati {len(result0)} alarm reali su {len(tot)}.")

    #file di alert non reali
    false_alerts = falseAttacks(test_file, attacks)

    save_to_json(false_alerts, "false_alerts.json")
    print(f"Sono stati salvati {len(false_alerts)} alarm falsi su {len(tot)}")