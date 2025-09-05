from llm import mock_llm,classify_alert,classify_all_alerts

def classify_alerts(alerts_list):

    alerts_list=classify_all_alerts(alerts_list)

    #for alert in alerts_list:
    #    temp = classify_alert(alert)
    #    print(f"Classificazione: {temp.classification}, Spiegazione: {temp.explanation}")
    #    alert["Classification"] = temp.classification
    #    alert["Explanation"] = temp.explanation
    return alerts_list