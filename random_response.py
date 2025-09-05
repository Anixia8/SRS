import random
import time

def response_generator():
    response = random.choice(
        [
            "Ciao, come posso aiutarti?",
            "Ciao, sono qui per aiutarti",
            "Ciao, fammi pure una domanda"
        ]
    )
    for word in response.split():
        yield word + " "
        time.sleep(0.05)